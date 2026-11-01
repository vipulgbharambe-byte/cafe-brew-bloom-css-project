'use strict';

/*
 * Brew & Bloom add-on server.
 * Uses Node.js built-ins only. Existing original HTML and style.css are served
 * unchanged on disk; add-on assets are injected into original HTML responses.
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { URL } = require('node:url');

const ROOT = __dirname;
const DATA_DIR = path.join(ROOT, 'data');
const DB_FILE = path.join(DATA_DIR, 'app-data.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');

function loadEnv() {
  const file = path.join(ROOT, '.env');
  if (!fs.existsSync(file)) return;
  for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith('#')) continue;
    const idx = trimmed.indexOf('=');
    if (idx < 1) continue;
    const key = trimmed.slice(0, idx).trim();
    let value = trimmed.slice(idx + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    if (!process.env[key]) process.env[key] = value;
  }
}
loadEnv();

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || (process.env.NODE_ENV === 'production' ? '' : 'local-development-only-change-this-secret-please');
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
if (IS_PRODUCTION && (!SESSION_SECRET || SESSION_SECRET.length < 32 || SESSION_SECRET.includes('local-only-change'))) {
  console.error('Startup blocked: set a SESSION_SECRET of at least 32 characters in production.');
  process.exit(1);
}

fs.mkdirSync(DATA_DIR, { recursive: true });
const seedProducts = JSON.parse(fs.readFileSync(PRODUCTS_FILE, 'utf8'));
const emptyDb = () => ({
  users: [], sessions: {}, products: seedProducts, orders: [], tickets: [],
  partnerApplications: [], reservations: [], inventory: [], auditLogs: [],
  otpChallenges: {}, paymentEvents: [], idempotencyKeys: {}, settings: { deliveryFee: 30, taxRate: 0, currency: 'INR', welcomeCoupon: 'WELCOME10', welcomePercent: 10, welcomeMaxDiscount: 75, welcomeMinimum: 299 }
});
let db;
if (fs.existsSync(DB_FILE)) {
  try { db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8')); }
  catch (error) { console.error('Could not read data/app-data.json:', error.message); process.exit(1); }
} else {
  db = emptyDb();
  fs.writeFileSync(DB_FILE, JSON.stringify(db, null, 2), { mode: 0o600 });
}
for (const [key, value] of Object.entries(emptyDb())) {
  if (db[key] === undefined) db[key] = value;
}
if (!Array.isArray(db.products) || db.products.length === 0) db.products = seedProducts;
// Add newly supplied source-menu items to an existing local catalogue without overwriting owner edits.
const knownProductIds = new Set(db.products.map(p => p.id));
for (const product of seedProducts) if (!knownProductIds.has(product.id)) db.products.push({ ...product });

function saveDb() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, DB_FILE);
}
function now() { return new Date().toISOString(); }
function uid(prefix = '') { return prefix + crypto.randomBytes(9).toString('hex'); }
function cleanText(value, max = 500) { return String(value ?? '').replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, max); }
function emailNorm(value) { return cleanText(value, 254).toLowerCase(); }
function money(n) { return Math.round(Number(n) * 100) / 100; }
function scryptHash(password, salt = crypto.randomBytes(16).toString('hex')) {
  return { salt, hash: crypto.scryptSync(password, salt, 64).toString('hex') };
}
function passwordMatches(password, user) {
  if (!user.passwordSalt || !user.passwordHash) return false;
  const actual = crypto.scryptSync(password, user.passwordSalt, 64);
  const expected = Buffer.from(user.passwordHash, 'hex');
  return expected.length === actual.length && crypto.timingSafeEqual(actual, expected);
}
function safeUser(user) {
  return { id: user.id, name: user.name, email: user.email, mobile: user.mobile || '', role: user.role, partnerApproved: !!user.partnerApproved, createdAt: user.createdAt };
}
function sign(value) { return crypto.createHmac('sha256', SESSION_SECRET).update(value).digest('base64url'); }
function parseCookies(header = '') {
  const result = {};
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i > 0) result[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return result;
}
function setCookie(res, name, value, options = {}) {
  const bits = [`${name}=${encodeURIComponent(value)}`, 'Path=/', 'SameSite=Lax', 'HttpOnly'];
  if (options.maxAge !== undefined) bits.push(`Max-Age=${options.maxAge}`);
  if (IS_PRODUCTION) bits.push('Secure');
  const existing = res.getHeader('Set-Cookie');
  const list = Array.isArray(existing) ? existing : (existing ? [existing] : []);
  list.push(bits.join('; '));
  res.setHeader('Set-Cookie', list);
}
function issueSession(res, user) {
  const id = uid('s_');
  const expiresAt = Date.now() + 7 * 24 * 60 * 60 * 1000;
  db.sessions[id] = { userId: user.id, expiresAt };
  saveDb();
  const payload = `${id}.${expiresAt}`;
  setCookie(res, 'cbb_session', `${payload}.${sign(payload)}`, { maxAge: 7 * 24 * 60 * 60 });
}
function currentUser(req) {
  const token = parseCookies(req.headers.cookie || '').cbb_session;
  if (!token) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [id, expText, signature] = parts;
  const payload = `${id}.${expText}`;
  const expected = Buffer.from(sign(payload));
  const actual = Buffer.from(signature);
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  const session = db.sessions[id];
  if (!session || Number(expText) < Date.now() || session.expiresAt < Date.now()) return null;
  return db.users.find(u => u.id === session.userId) || null;
}
function requireAuth(req, res, roles = []) {
  const user = currentUser(req);
  if (!user) { json(res, 401, { error: 'Please sign in to continue.' }); return null; }
  if (roles.length && !roles.includes(user.role)) { json(res, 403, { error: 'You do not have permission to perform this action.' }); return null; }
  if (user.role === 'delivery_partner' && !user.partnerApproved && !roles.includes('admin')) {
    json(res, 403, { error: 'Your delivery partner application is awaiting approval.' }); return null;
  }
  return user;
}
function audit(actor, action, entity, entityId, details = {}) {
  db.auditLogs.unshift({ id: uid('log_'), actorId: actor?.id || null, actorEmail: actor?.email || 'system', action, entity, entityId, details, createdAt: now() });
  db.auditLogs = db.auditLogs.slice(0, 3000);
}
function json(res, status, body) {
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' });
  res.end(JSON.stringify(body));
}
function readBody(req, limit = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let body = '';
    req.on('data', chunk => {
      body += chunk;
      if (Buffer.byteLength(body) > limit) { reject(Object.assign(new Error('Request is too large.'), { status: 413 })); req.destroy(); }
    });
    req.on('end', () => {
      if (!body) return resolve({});
      try { resolve(JSON.parse(body)); }
      catch { reject(Object.assign(new Error('Request must contain valid JSON.'), { status: 400 })); }
    });
    req.on('error', reject);
  });
}
function enforceSameOrigin(req, res) {
  if (req.headers['x-cbb-request'] !== '1') { json(res, 403, { error: 'Request validation failed. Refresh the page and try again.' }); return false; }
  const origin = req.headers.origin;
  if (origin) {
    const host = req.headers.host;
    try { if (new URL(origin).host !== host) { json(res, 403, { error: 'Cross-origin request blocked.' }); return false; } }
    catch { json(res, 403, { error: 'Invalid request origin.' }); return false; }
  }
  return true;
}
const rateBuckets = new Map();
function rateLimit(req, res, bucket, max = 12, windowMs = 10 * 60 * 1000) {
  const ip = req.socket.remoteAddress || 'local';
  const key = `${bucket}:${ip}`;
  const stamp = Date.now();
  let entry = rateBuckets.get(key);
  if (!entry || stamp > entry.resetAt) entry = { count: 0, resetAt: stamp + windowMs };
  entry.count++;
  rateBuckets.set(key, entry);
  if (entry.count > max) { json(res, 429, { error: 'Too many attempts. Please try again later.' }); return false; }
  return true;
}
function publicProduct(p) { return { id: p.id, name: p.name, category: p.category, description: p.description, price: p.price, available: p.available !== false, featured: !!p.featured }; }
function findOrder(id) { return db.orders.find(o => o.id === id || o.orderNumber === id); }
function getOrderForUser(order, user) { return order && (user.role === 'admin' || order.userId === user.id); }
function makeOrderNumber() { return `BB${new Date().getFullYear()}${crypto.randomBytes(3).toString('hex').toUpperCase()}`; }
function safeEqualHex(a, b) {
  try { const x = Buffer.from(a, 'hex'); const y = Buffer.from(b, 'hex'); return x.length === y.length && x.length > 0 && crypto.timingSafeEqual(x, y); } catch { return false; }
}
async function razorpayRequest(endpoint, method = 'GET', body) {
  const keyId = process.env.RAZORPAY_KEY_ID;
  const secret = process.env.RAZORPAY_KEY_SECRET;
  if (!keyId || !secret) throw Object.assign(new Error('Razorpay is not configured. Add your test-mode keys in .env before enabling online payments.'), { status: 503 });
  const auth = Buffer.from(`${keyId}:${secret}`).toString('base64');
  const response = await fetch(`https://api.razorpay.com/v1/${endpoint}`, {
    method, headers: { Authorization: `Basic ${auth}`, 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Object.assign(new Error(data.error?.description || 'Payment provider request failed.'), { status: 502 });
  return data;
}

// Create the first administrator from local environment configuration.
const adminEmail = emailNorm(process.env.ADMIN_EMAIL || 'admin@cafebrewbloom.local');
const adminPassword = process.env.ADMIN_PASSWORD || (IS_PRODUCTION ? '' : 'ChangeThisAdminPassword123!');
if (adminPassword && !db.users.some(u => u.email === adminEmail)) {
  const pw = scryptHash(adminPassword);
  db.users.push({ id: uid('usr_'), name: 'Cafe Administrator', email: adminEmail, role: 'admin', mobile: '', passwordSalt: pw.salt, passwordHash: pw.hash, createdAt: now(), partnerApproved: false });
  saveDb();
  if (!IS_PRODUCTION) console.log(`Local admin created: ${adminEmail} / ${adminPassword} (change this before deployment)`);
}
if (IS_PRODUCTION && (!adminPassword || adminPassword === 'ChangeThisAdminPassword123!')) {
  console.error('Startup blocked: set a unique ADMIN_PASSWORD in the production environment.');
  process.exit(1);
}

async function api(req, res, url) {
  const method = req.method;
  const pathname = url.pathname;
  const user = currentUser(req);

  if (method === 'GET' && pathname === '/api/health') return json(res, 200, { ok: true, service: 'Brew & Bloom', timestamp: now() });
  if (method === 'GET' && pathname === '/api/products') {
    const products = db.products.filter(p => !p.archived).map(publicProduct);
    return json(res, 200, { products });
  }
  if (method === 'GET' && pathname === '/api/settings/public') {
    return json(res, 200, { deliveryFee: db.settings.deliveryFee, taxRate: db.settings.taxRate, welcomeCoupon: db.settings.welcomeCoupon, welcomePercent: db.settings.welcomePercent, welcomeMaxDiscount: db.settings.welcomeMaxDiscount, welcomeMinimum: db.settings.welcomeMinimum, razorpayEnabled: !!(process.env.RAZORPAY_KEY_ID && process.env.RAZORPAY_KEY_SECRET), googleOAuthEnabled: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET), developmentOtpEnabled: !IS_PRODUCTION });
  }
  if (method === 'GET' && pathname === '/api/auth/me') return json(res, 200, { user: user ? safeUser(user) : null });

  if (method === 'POST' && pathname === '/api/auth/register') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'register', 8)) return;
    const body = await readBody(req);
    const name = cleanText(body.name, 100), email = emailNorm(body.email), mobile = cleanText(body.mobile, 20).replace(/[\s-]/g, ''), password = String(body.password || '');
    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || password.length < 8 || password.length > 128 || (mobile && !/^\+?[0-9]{10,15}$/.test(mobile.replace(/[\s-]/g, '')))) return json(res, 400, { error: 'Enter your name, a valid email, a valid mobile number (if supplied) and a password of 8 to 128 characters.' });
    if (db.users.some(u => u.email === email)) return json(res, 409, { error: 'An account with this email already exists.' });
    if (mobile && db.users.some(u => u.mobile && u.mobile.replace(/[\s-]/g, '') === mobile.replace(/[\s-]/g, '') && u.role === 'customer')) return json(res, 409, { error: 'This mobile number is already linked to a customer account.' });
    const pw = scryptHash(password);
    const created = { id: uid('usr_'), name, email, mobile, role: 'customer', passwordSalt: pw.salt, passwordHash: pw.hash, createdAt: now(), partnerApproved: false, loyaltyPoints: 0 };
    db.users.push(created); audit(created, 'customer.registered', 'user', created.id); issueSession(res, created);
    return json(res, 201, { user: safeUser(created) });
  }
  if (method === 'POST' && pathname === '/api/auth/login') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'login', 10)) return;
    const body = await readBody(req); const email = emailNorm(body.email); const password = String(body.password || '');
    if (password.length > 128) return json(res, 400, { error: 'Password is too long.' });
    const found = db.users.find(u => u.email === email);
    if (!found || !passwordMatches(password, found)) return json(res, 401, { error: 'Email or password is incorrect.' });
    if (found.role === 'delivery_partner' && !found.partnerApproved) return json(res, 403, { error: 'Your partner application has not been approved yet.' });
    issueSession(res, found); return json(res, 200, { user: safeUser(found) });
  }
  if (method === 'POST' && pathname === '/api/auth/logout') {
    if (!enforceSameOrigin(req, res)) return;
    const token = parseCookies(req.headers.cookie || '').cbb_session;
    const id = token?.split('.')[0]; if (id) delete db.sessions[id]; saveDb();
    setCookie(res, 'cbb_session', '', { maxAge: 0 }); return json(res, 200, { ok: true });
  }
  if (method === 'POST' && pathname === '/api/auth/request-otp') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'otp', 5)) return;
    const body = await readBody(req); const mobile = cleanText(body.mobile, 20).replace(/[^+0-9]/g, '');
    if (!/^\+?[0-9]{10,15}$/.test(mobile)) return json(res, 400, { error: 'Enter a valid mobile number including country code if needed.' });
    if (IS_PRODUCTION) return json(res, 503, { error: 'Mobile OTP delivery is not configured. Configure an SMS provider before enabling this sign-in method.' });
    const code = String(crypto.randomInt(100000, 1000000)); const salt = crypto.randomBytes(12).toString('hex');
    db.otpChallenges[mobile] = { salt, hash: crypto.scryptSync(code, salt, 32).toString('hex'), expiresAt: Date.now() + 5 * 60 * 1000 };
    saveDb();
    console.log(`[DEVELOPMENT OTP] ${mobile}: ${code}`);
    return json(res, 200, { ok: true, message: 'Development OTP generated. Check the server terminal.', developmentCode: code });
  }
  if (method === 'POST' && pathname === '/api/auth/verify-otp') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'otp_verify', 8)) return;
    const body = await readBody(req); const mobile = cleanText(body.mobile, 20).replace(/[^+0-9]/g, ''); const code = String(body.code || '');
    const challenge = db.otpChallenges[mobile];
    if (!challenge || challenge.expiresAt < Date.now() || !/^\d{6}$/.test(code)) return json(res, 400, { error: 'The OTP is invalid or expired.' });
    const actual = crypto.scryptSync(code, challenge.salt, 32); const expected = Buffer.from(challenge.hash, 'hex');
    if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return json(res, 400, { error: 'The OTP is invalid or expired.' });
    delete db.otpChallenges[mobile];
    let account = db.users.find(u => u.mobile === mobile && u.role === 'customer');
    if (!account) { account = { id: uid('usr_'), name: `Customer ${mobile.slice(-4)}`, email: '', mobile, role: 'customer', createdAt: now(), partnerApproved: false, loyaltyPoints: 0 }; db.users.push(account); }
    saveDb(); issueSession(res, account); return json(res, 200, { user: safeUser(account) });
  }

  if (method === 'POST' && pathname === '/api/partner/apply') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'partner', 5)) return;
    const body = await readBody(req); const name = cleanText(body.name, 100); const email = emailNorm(body.email); const mobile = cleanText(body.mobile, 20).replace(/[\s-]/g, ''); const vehicle = cleanText(body.vehicle, 40); const password = String(body.password || '');
    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || !/^\+?[0-9]{10,15}$/.test(mobile.replace(/[\s-]/g, '')) || !vehicle || password.length < 8 || password.length > 128) return json(res, 400, { error: 'Complete all required fields with a valid mobile number. Password must contain 8 to 128 characters.' });
    if (db.users.some(u => u.email === email)) return json(res, 409, { error: 'An account with this email already exists.' });
    if (db.users.some(u => u.mobile && u.mobile.replace(/[\s-]/g, '') === mobile.replace(/[\s-]/g, ''))) return json(res, 409, { error: 'This mobile number is already linked to an account.' });
    const pw = scryptHash(password); const partner = { id: uid('usr_'), name, email, mobile, role: 'delivery_partner', vehicle, passwordSalt: pw.salt, passwordHash: pw.hash, partnerApproved: false, createdAt: now(), loyaltyPoints: 0 };
    db.users.push(partner); const application = { id: uid('pa_'), userId: partner.id, name, email, mobile, vehicle, status: 'pending', createdAt: now() };
    db.partnerApplications.unshift(application); audit(null, 'partner.application_submitted', 'partner_application', application.id); saveDb();
    return json(res, 201, { ok: true, message: 'Application received. Sign-in will be enabled after administrator approval.' });
  }

  if (method === 'GET' && pathname === '/api/orders') {
    const who = requireAuth(req, res, ['customer', 'admin']); if (!who) return;
    const orders = who.role === 'admin' ? db.orders : db.orders.filter(o => o.userId === who.id);
    return json(res, 200, { orders: orders.slice(0, 100).map(({ deliveryOtp, ...o }) => o) });
  }
  if (method === 'POST' && pathname === '/api/orders') {
    if (!enforceSameOrigin(req, res)) return;
    const who = requireAuth(req, res, ['customer']); if (!who) return;
    const body = await readBody(req); const idem = cleanText(body.idempotencyKey, 120);
    if (!['razorpay', 'pay_at_counter'].includes(body.paymentMethod)) return json(res, 400, { error: 'Choose a valid payment method.' });
    if (body.paymentMethod === 'razorpay' && (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET)) return json(res, 503, { error: 'Online payment is not configured yet. The café administrator must add Razorpay test credentials.' });
    if (idem && db.idempotencyKeys[idem]) { const previous = findOrder(db.idempotencyKeys[idem]); if (previous && previous.userId === who.id) { const safePrevious = { ...previous }; delete safePrevious.deliveryOtp; return json(res, 200, { order: safePrevious, idempotentReplay: true }); } }
    const items = Array.isArray(body.items) ? body.items : [];
    if (!items.length || items.length > 50) return json(res, 400, { error: 'Your cart is empty or contains too many items.' });
    const calculated = [];
    for (const item of items) {
      const product = db.products.find(p => p.id === cleanText(item.productId, 100) && !p.archived && p.available !== false);
      const qty = Number(item.quantity);
      if (!product || !Number.isInteger(qty) || qty < 1 || qty > 20) return json(res, 400, { error: 'A product is unavailable or has an invalid quantity. Please refresh your cart.' });
      calculated.push({ productId: product.id, name: product.name, quantity: qty, unitPrice: money(product.price), lineTotal: money(product.price * qty) });
    }
    const subtotal = money(calculated.reduce((sum, item) => sum + item.lineTotal, 0));
    const hasPriorOrder = db.orders.some(o => o.userId === who.id && ['placed', 'accepted', 'preparing', 'ready', 'out_for_delivery', 'delivered'].includes(o.status));
    let discount = 0; const coupon = cleanText(body.coupon, 40).toUpperCase();
    if (coupon && coupon === String(db.settings.welcomeCoupon).toUpperCase() && !hasPriorOrder && subtotal >= Number(db.settings.welcomeMinimum)) {
      discount = Math.min(subtotal * Number(db.settings.welcomePercent) / 100, Number(db.settings.welcomeMaxDiscount));
    } else if (coupon) return json(res, 400, { error: 'This coupon is invalid or its conditions are not met.' });
    const deliveryFee = body.orderType === 'takeaway' || body.orderType === 'dine_in' ? 0 : Number(db.settings.deliveryFee);
    const taxable = Math.max(0, subtotal - discount + deliveryFee);
    const tax = money(taxable * Number(db.settings.taxRate) / 100);
    const total = money(taxable + tax);
    const order = {
      id: uid('ord_'), orderNumber: makeOrderNumber(), userId: who.id, customerName: who.name, customerEmail: who.email, customerMobile: who.mobile,
      items: calculated, subtotal, discount: money(discount), coupon: discount ? coupon : '', deliveryFee, tax, total,
      orderType: ['delivery', 'takeaway', 'dine_in'].includes(body.orderType) ? body.orderType : 'delivery',
      address: cleanText(body.address, 500), instructions: cleanText(body.instructions, 500), paymentMethod: body.paymentMethod === 'razorpay' ? 'razorpay' : 'pay_at_counter',
      paymentStatus: 'pending', status: 'placed', refundStatus: 'none', deliveryPartnerId: null, deliveryOtp: String(crypto.randomInt(100000, 1000000)), statusHistory: [{ status: 'placed', at: now(), by: who.id }], createdAt: now(), updatedAt: now()
    };
    if (order.orderType === 'delivery' && order.address.length < 8) return json(res, 400, { error: 'Enter a complete delivery address.' });
    if (order.orderType === 'delivery' && order.paymentMethod !== 'razorpay') return json(res, 400, { error: 'Delivery orders require online payment in this installation. Select Razorpay at checkout.' });
    db.orders.unshift(order); if (idem) db.idempotencyKeys[idem] = order.id; audit(who, 'order.placed', 'order', order.id, { orderNumber: order.orderNumber, total }); saveDb();
    return json(res, 201, { order: { ...order, deliveryOtp: undefined } });
  }
  const orderRoute = pathname.match(/^\/api\/orders\/([^/]+)$/);
  if (method === 'GET' && orderRoute) {
    const who = requireAuth(req, res, ['customer', 'admin']); if (!who) return;
    const order = findOrder(decodeURIComponent(orderRoute[1]));
    if (!getOrderForUser(order, who)) return json(res, 404, { error: 'Order not found.' });
    const safe = { ...order }; if (who.id !== order.userId) delete safe.deliveryOtp; return json(res, 200, { order: safe });
  }

  if (method === 'POST' && pathname === '/api/payments/razorpay/create') {
    if (!enforceSameOrigin(req, res)) return;
    const who = requireAuth(req, res, ['customer']); if (!who) return;
    const body = await readBody(req); const order = findOrder(cleanText(body.orderId, 100));
    if (!order || order.userId !== who.id) return json(res, 404, { error: 'Order not found.' });
    if (order.paymentMethod !== 'razorpay' || order.paymentStatus !== 'pending') return json(res, 400, { error: 'This order is not awaiting online payment.' });
    try {
      const paymentOrder = await razorpayRequest('orders', 'POST', { amount: Math.round(order.total * 100), currency: 'INR', receipt: order.orderNumber, notes: { appOrderId: order.id } });
      order.razorpayOrderId = paymentOrder.id; order.updatedAt = now(); saveDb();
      return json(res, 200, { keyId: process.env.RAZORPAY_KEY_ID, paymentOrderId: paymentOrder.id, amount: paymentOrder.amount, currency: paymentOrder.currency, name: 'Brew & Bloom', description: `Order ${order.orderNumber}` });
    } catch (error) { return json(res, error.status || 502, { error: error.message }); }
  }
  if (method === 'POST' && pathname === '/api/payments/razorpay/verify') {
    if (!enforceSameOrigin(req, res)) return;
    const who = requireAuth(req, res, ['customer']); if (!who) return;
    const body = await readBody(req); const order = findOrder(cleanText(body.orderId, 100));
    if (!order || order.userId !== who.id || !order.razorpayOrderId || order.razorpayOrderId !== body.razorpay_order_id) return json(res, 400, { error: 'Payment details do not match this order.' });
    const secret = process.env.RAZORPAY_KEY_SECRET || '';
    const expected = crypto.createHmac('sha256', secret).update(`${body.razorpay_order_id}|${body.razorpay_payment_id}`).digest('hex');
    if (!secret || !safeEqualHex(expected, String(body.razorpay_signature || ''))) return json(res, 400, { error: 'Payment signature verification failed.' });
    try {
      const payment = await razorpayRequest(`payments/${encodeURIComponent(body.razorpay_payment_id)}`);
      if (payment.order_id !== order.razorpayOrderId || !['captured', 'authorized'].includes(payment.status)) return json(res, 400, { error: 'Payment is not confirmed by Razorpay yet.' });
      order.razorpayPaymentId = payment.id; order.paymentStatus = payment.status === 'captured' ? 'paid' : 'authorized'; order.updatedAt = now();
      order.statusHistory.push({ status: order.status, at: now(), by: who.id, note: `Payment ${order.paymentStatus}` }); audit(who, 'payment.verified', 'order', order.id, { paymentId: payment.id, status: payment.status }); saveDb();
      return json(res, 200, { ok: true, paymentStatus: order.paymentStatus, orderNumber: order.orderNumber });
    } catch (error) { return json(res, error.status || 502, { error: error.message }); }
  }
  if (method === 'POST' && pathname === '/api/payments/razorpay/webhook') {
    const raw = await new Promise((resolve, reject) => { const chunks = []; req.on('data', c => chunks.push(c)); req.on('end', () => resolve(Buffer.concat(chunks))); req.on('error', reject); });
    const signature = req.headers['x-razorpay-signature']; const hookSecret = process.env.RAZORPAY_WEBHOOK_SECRET || '';
    if (!hookSecret || !signature) return json(res, 400, { error: 'Webhook signature is missing.' });
    const computed = crypto.createHmac('sha256', hookSecret).update(raw).digest('hex');
    if (!safeEqualHex(computed, signature)) return json(res, 400, { error: 'Invalid webhook signature.' });
    const event = JSON.parse(raw.toString('utf8')); const eventId = req.headers['x-razorpay-event-id'] || uid('evt_');
    if (!db.paymentEvents.some(e => e.id === eventId)) {
      db.paymentEvents.push({ id: eventId, event: event.event, receivedAt: now() });
      const entity = event.payload?.payment?.entity;
      if (entity?.order_id) {
        const order = db.orders.find(o => o.razorpayOrderId === entity.order_id);
        if (order) {
          if (event.event === 'payment.captured') { order.paymentStatus = 'paid'; order.razorpayPaymentId = entity.id; }
          if (event.event === 'payment.failed') { order.paymentStatus = 'failed'; order.razorpayPaymentId = entity.id; }
          order.updatedAt = now();
        }
      }
      const refundEntity = event.payload?.refund?.entity;
      if (refundEntity?.payment_id) {
        const order = db.orders.find(o => o.razorpayPaymentId === refundEntity.payment_id);
        if (order) { order.refundStatus = event.event === 'refund.processed' ? 'processed' : event.event === 'refund.failed' ? 'failed' : order.refundStatus; order.updatedAt = now(); }
      }
      saveDb();
    }
    return json(res, 200, { received: true });
  }

  if (method === 'GET' && pathname === '/api/support/tickets') {
    const who = requireAuth(req, res, ['customer', 'admin']); if (!who) return;
    const list = who.role === 'admin' ? db.tickets : db.tickets.filter(t => t.userId === who.id);
    return json(res, 200, { tickets: list.slice(0, 100) });
  }
  if (method === 'POST' && pathname === '/api/support/tickets') {
    if (!enforceSameOrigin(req, res)) return;
    const who = requireAuth(req, res, ['customer']); if (!who) return;
    const body = await readBody(req); const subject = cleanText(body.subject, 120), message = cleanText(body.message, 2000), category = cleanText(body.category, 50);
    if (subject.length < 4 || message.length < 10) return json(res, 400, { error: 'Enter a subject and a message with at least 10 characters.' });
    const ticket = { id: uid('tic_'), ticketNumber: `SUP-${Date.now().toString().slice(-7)}`, userId: who.id, customerName: who.name, subject, category, messages: [{ id: uid('msg_'), senderId: who.id, senderName: who.name, message, at: now() }], status: 'open', priority: 'normal', createdAt: now(), updatedAt: now() };
    db.tickets.unshift(ticket); saveDb(); return json(res, 201, { ticket });
  }

  if (method === 'POST' && pathname === '/api/reservations') {
    if (!enforceSameOrigin(req, res)) return;
    const body = await readBody(req); const name = cleanText(body.name, 100), email = emailNorm(body.email), mobile = cleanText(body.mobile, 20), date = cleanText(body.date, 20), time = cleanText(body.time, 10), guests = Number(body.guests);
    if (name.length < 2 || !/^\S+@\S+\.\S+$/.test(email) || mobile.length < 10 || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^\d{2}:\d{2}$/.test(time) || !Number.isInteger(guests) || guests < 1 || guests > 20) return json(res, 400, { error: 'Please complete all reservation fields correctly.' });
    if (new Date(`${date}T${time}:00`) < new Date()) return json(res, 400, { error: 'Choose a future date and time.' });
    const reservation = { id: uid('res_'), reference: `RSV-${Date.now().toString().slice(-7)}`, name, email, mobile, date, time, guests, notes: cleanText(body.notes, 500), status: 'requested', createdAt: now() };
    db.reservations.unshift(reservation); saveDb(); return json(res, 201, { reservation });
  }

  if (method === 'GET' && pathname === '/api/partner/deliveries') {
    const who = requireAuth(req, res, ['delivery_partner']); if (!who) return;
    return json(res, 200, { orders: db.orders.filter(o => o.deliveryPartnerId === who.id).map(({ deliveryOtp, ...o }) => o) });
  }
  if (method === 'POST' && pathname === '/api/partner/deliveries/status') {
    if (!enforceSameOrigin(req, res)) return;
    const who = requireAuth(req, res, ['delivery_partner']); if (!who) return;
    const body = await readBody(req); const order = findOrder(body.orderId);
    if (!order || order.deliveryPartnerId !== who.id) return json(res, 404, { error: 'Assigned delivery not found.' });
    const transitions = { delivery_assigned: ['picked_up'], picked_up: ['out_for_delivery'], out_for_delivery: ['delivered'] };
    if (!transitions[order.status]?.includes(body.status)) return json(res, 409, { error: 'This delivery status transition is not allowed.' });
    if (body.status === 'delivered' && String(body.otp || '') !== order.deliveryOtp) return json(res, 400, { error: 'Delivery OTP does not match.' });
    order.status = body.status; order.updatedAt = now(); order.statusHistory.push({ status: body.status, at: now(), by: who.id });
    if (body.status === 'delivered') { order.deliveredAt = now(); const customer = db.users.find(u => u.id === order.userId); if (customer) { customer.loyaltyPoints = Number(customer.loyaltyPoints || 0) + Math.floor(order.subtotal / 100); } }
    saveDb(); return json(res, 200, { ok: true, status: order.status });
  }

  if (pathname.startsWith('/api/admin/')) {
    const admin = requireAuth(req, res, ['admin']); if (!admin) return;
    if (method === 'GET' && pathname === '/api/admin/overview') {
      const today = new Date().toISOString().slice(0, 10); const dayOrders = db.orders.filter(o => o.createdAt.slice(0, 10) === today);
      return json(res, 200, { metrics: { ordersToday: dayOrders.length, salesToday: money(dayOrders.filter(o => o.paymentStatus === 'paid').reduce((s, o) => s + o.total, 0)), pendingOrders: db.orders.filter(o => !['delivered', 'cancelled'].includes(o.status)).length, openTickets: db.tickets.filter(t => !['resolved', 'closed'].includes(t.status)).length, pendingPartners: db.partnerApplications.filter(p => p.status === 'pending').length, products: db.products.filter(p => !p.archived).length }, recentOrders: db.orders.slice(0, 8), lowStock: db.inventory.filter(i => i.quantity <= i.reorderLevel).slice(0, 8) });
    }
    if (method === 'POST' && pathname === '/api/admin/refunds') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const order = findOrder(body.orderId);
      if (!order || order.paymentStatus !== 'paid' || !order.razorpayPaymentId) return json(res, 400, { error: 'Only a Razorpay-paid order with a verified payment ID can be refunded from this screen.' });
      if (order.refundStatus === 'initiated' || order.refundStatus === 'processed') return json(res, 409, { error: 'A refund has already been initiated for this order.' });
      const amount = body.amount === undefined || body.amount === '' ? order.total : Number(body.amount);
      if (!Number.isFinite(amount) || amount <= 0 || amount > order.total) return json(res, 400, { error: 'Enter a valid refund amount up to the paid order total.' });
      try {
        const refund = await razorpayRequest(`payments/${encodeURIComponent(order.razorpayPaymentId)}/refund`, 'POST', { amount: Math.round(amount * 100), notes: { orderNumber: order.orderNumber, reason: cleanText(body.reason, 200) } });
        order.refundId = refund.id; order.refundAmount = money(amount); order.refundStatus = refund.status === 'processed' ? 'processed' : 'initiated'; order.updatedAt = now();
        audit(admin, 'payment.refund_initiated', 'order', order.id, { refundId: refund.id, amount }); saveDb();
        return json(res, 200, { ok: true, refundStatus: order.refundStatus, refundId: refund.id });
      } catch (error) { return json(res, error.status || 502, { error: error.message }); }
    }
    if (method === 'GET' && pathname === '/api/admin/orders') return json(res, 200, { orders: db.orders.slice(0, 250).map(({ deliveryOtp, ...o }) => o) });
    if (method === 'POST' && pathname === '/api/admin/orders/status') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const order = findOrder(body.orderId); const valid = ['accepted', 'preparing', 'ready', 'cancelled', 'out_for_delivery'];
      if (!order || !valid.includes(body.status)) return json(res, 400, { error: 'Order or status is invalid.' });
      if (order.status === 'delivered' || order.status === 'cancelled') return json(res, 409, { error: 'This order is already closed.' });
      order.status = body.status; order.updatedAt = now(); order.statusHistory.push({ status: body.status, at: now(), by: admin.id }); audit(admin, 'order.status_changed', 'order', order.id, { status: body.status }); saveDb(); return json(res, 200, { order });
    }
    if (method === 'GET' && pathname === '/api/admin/products') return json(res, 200, { products: db.products });
    if (method === 'POST' && pathname === '/api/admin/products') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const name = cleanText(body.name, 100), category = cleanText(body.category, 50), description = cleanText(body.description, 500), price = Number(body.price);
      if (name.length < 2 || !category || !Number.isFinite(price) || price <= 0 || price > 100000) return json(res, 400, { error: 'Enter a product name, category and valid price.' });
      const id = cleanText(body.id, 100) || name.toLowerCase().normalize('NFKD').replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '') + '-' + crypto.randomBytes(2).toString('hex');
      if (db.products.some(p => p.id === id)) return json(res, 409, { error: 'A product with this identifier already exists.' });
      const product = { id, name, category, description, price: money(price), available: body.available !== false, featured: !!body.featured, createdAt: now() };
      db.products.push(product); audit(admin, 'product.created', 'product', id); saveDb(); return json(res, 201, { product });
    }
    const productRoute = pathname.match(/^\/api\/admin\/products\/([^/]+)$/);
    if (method === 'PATCH' && productRoute) {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const product = db.products.find(p => p.id === decodeURIComponent(productRoute[1])); if (!product) return json(res, 404, { error: 'Product not found.' });
      if (body.name !== undefined) product.name = cleanText(body.name, 100);
      if (body.description !== undefined) product.description = cleanText(body.description, 500);
      if (body.category !== undefined) product.category = cleanText(body.category, 50);
      if (body.price !== undefined) { const price = Number(body.price); if (!Number.isFinite(price) || price <= 0) return json(res, 400, { error: 'Price must be greater than zero.' }); product.price = money(price); }
      if (body.available !== undefined) product.available = !!body.available;
      if (body.archived !== undefined) product.archived = !!body.archived;
      product.updatedAt = now(); audit(admin, 'product.updated', 'product', product.id); saveDb(); return json(res, 200, { product });
    }
    if (method === 'GET' && pathname === '/api/admin/partners') return json(res, 200, { applications: db.partnerApplications });
    if (method === 'POST' && pathname === '/api/admin/partners/review') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const app = db.partnerApplications.find(p => p.id === body.applicationId); if (!app || !['approved', 'rejected'].includes(body.status)) return json(res, 400, { error: 'Application or decision is invalid.' });
      app.status = body.status; app.reviewedAt = now(); app.reviewedBy = admin.id; const partner = db.users.find(u => u.id === app.userId); if (partner) partner.partnerApproved = body.status === 'approved';
      audit(admin, 'partner.application_reviewed', 'partner_application', app.id, { status: app.status }); saveDb(); return json(res, 200, { application: app });
    }
    if (method === 'POST' && pathname === '/api/admin/delivery/assign') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const order = findOrder(body.orderId); const partner = db.users.find(u => u.id === body.partnerId && u.role === 'delivery_partner' && u.partnerApproved);
      if (!order || !partner || order.orderType !== 'delivery' || order.status !== 'ready' || order.paymentStatus !== 'paid') return json(res, 400, { error: 'A delivery order can be assigned only after it is ready and its payment is verified as paid.' });
      order.deliveryPartnerId = partner.id; order.status = 'delivery_assigned'; order.updatedAt = now(); order.statusHistory.push({ status: 'delivery_assigned', at: now(), by: admin.id, note: `Assigned to ${partner.name}` }); saveDb(); return json(res, 200, { ok: true });
    }
    if (method === 'GET' && pathname === '/api/admin/tickets') return json(res, 200, { tickets: db.tickets });
    if (method === 'POST' && pathname === '/api/admin/tickets/reply') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const ticket = db.tickets.find(t => t.id === body.ticketId); const message = cleanText(body.message, 2000);
      if (!ticket || message.length < 2) return json(res, 400, { error: 'Ticket or reply is invalid.' });
      ticket.messages.push({ id: uid('msg_'), senderId: admin.id, senderName: admin.name, message, at: now() }); ticket.status = 'in_progress'; ticket.updatedAt = now(); saveDb(); return json(res, 200, { ticket });
    }
    if (method === 'GET' && pathname === '/api/admin/reservations') return json(res, 200, { reservations: db.reservations });
    if (method === 'POST' && pathname === '/api/admin/reservations/status') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const reservation = db.reservations.find(r => r.id === body.reservationId);
      if (!reservation || !['confirmed', 'declined', 'completed'].includes(body.status)) return json(res, 400, { error: 'Reservation or decision is invalid.' });
      reservation.status = body.status; reservation.reviewedAt = now(); reservation.reviewedBy = admin.id; saveDb();
      return json(res, 200, { reservation });
    }
    if (method === 'PATCH' && pathname === '/api/admin/settings') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req);
      for (const key of ['deliveryFee', 'taxRate', 'welcomePercent', 'welcomeMaxDiscount', 'welcomeMinimum']) if (body[key] !== undefined) { const val = Number(body[key]); const max = ['taxRate', 'welcomePercent'].includes(key) ? 100 : 100000; if (!Number.isFinite(val) || val < 0 || val > max) return json(res, 400, { error: `Invalid setting: ${key}` }); db.settings[key] = val; }
      if (body.welcomeCoupon) db.settings.welcomeCoupon = cleanText(body.welcomeCoupon, 40).toUpperCase();
      audit(admin, 'settings.updated', 'settings', 'business'); saveDb(); return json(res, 200, { settings: db.settings });
    }
    if (method === 'GET' && pathname === '/api/admin/inventory') return json(res, 200, { inventory: db.inventory });
    if (method === 'POST' && pathname === '/api/admin/inventory') {
      if (!enforceSameOrigin(req, res)) return;
      const body = await readBody(req); const name = cleanText(body.name, 100), unit = cleanText(body.unit, 20), quantity = Number(body.quantity), reorderLevel = Number(body.reorderLevel || 0);
      if (!name || !unit || !Number.isFinite(quantity) || quantity < 0 || !Number.isFinite(reorderLevel) || reorderLevel < 0) return json(res, 400, { error: 'Enter a valid item, unit, quantity and reorder level.' });
      const item = { id: uid('inv_'), name, unit, quantity, reorderLevel, expiryDate: cleanText(body.expiryDate, 20), updatedAt: now() }; db.inventory.unshift(item); saveDb(); return json(res, 201, { item });
    }
    if (method === 'GET' && pathname === '/api/admin/audit') return json(res, 200, { logs: db.auditLogs.slice(0, 300) });
    if (method === 'GET' && pathname === '/api/admin/users') return json(res, 200, { users: db.users.map(safeUser) });
    return json(res, 404, { error: 'Admin endpoint not found.' });
  }

  if (method === 'POST' && pathname === '/api/chat') {
    if (!enforceSameOrigin(req, res) || !rateLimit(req, res, 'chat', 30, 60 * 1000)) return;
    const body = await readBody(req); const question = cleanText(body.message, 1000);
    if (!question) return json(res, 400, { error: 'Enter a message.' });
    const q = question.toLowerCase();
    const matched = db.products.filter(p => !p.archived && (q.includes(p.name.toLowerCase()) || q.includes(p.category.toLowerCase()))).slice(0, 6);
    let answer;
    if (/\b(my order|order status|track.*order|where.*order|order.*status)\b/.test(q)) {
      const chatUser = currentUser(req);
      if (!chatUser || chatUser.role !== 'customer') answer = 'Please sign in to your customer account first. I can then look up only orders belonging to that signed-in account.';
      else {
        const ref = q.match(/bb\d{4}[a-f0-9]{6}/i)?.[0];
        const userOrders = db.orders.filter(o => o.userId === chatUser.id);
        const wanted = ref ? userOrders.find(o => o.orderNumber.toLowerCase() === ref.toLowerCase()) : userOrders[0];
        answer = wanted ? `Your order ${wanted.orderNumber} is currently ${wanted.status.replaceAll('_', ' ')}. Payment status: ${wanted.paymentStatus}.` : 'I could not find an order for your account yet. Check your Orders page or contact customer care.';
      }
    }
    else if (matched.length) answer = matched.map(p => `${p.name} — ₹${p.price}. ${p.available === false ? 'Currently unavailable.' : p.description}`).join('\n');
    else if (/hour|open|timing|close/.test(q)) answer = 'Our opening hours have not yet been configured in the business settings. Please contact the café team to confirm today’s hours.';
    else if (/deliver|delivery|charge|fee/.test(q)) answer = `The configured delivery fee is ₹${db.settings.deliveryFee}. Delivery availability depends on the address and the café’s delivery area.`;
    else if (/refund|cancel/.test(q)) answer = 'Refunds and cancellations depend on the order status and the café’s approved policy. Please create a support ticket so the team can review your order.';
    else if (/reserve|table|booking/.test(q)) answer = 'You can submit a table request from the Reservations page. The team will confirm availability.';
    else if (/hello|hi\b|hey/.test(q)) answer = 'Hello! I can help with menu items, prices, delivery information, reservations, your own order status after sign-in and support.';
    else answer = 'I can help with the menu, product prices, delivery fee, reservations, your own order status after sign-in and support. I do not have verified information for that request yet, so please contact customer care for confirmation.';
    if (process.env.AI_PROVIDER_URL && process.env.AI_PROVIDER_API_KEY && process.env.AI_MODEL && !/\b(my order|order status|track.*order|where.*order|order.*status)\b/.test(q)) {
      try {
        const context = db.products.filter(p => !p.archived).map(p => `${p.name}: ₹${p.price}; ${p.category}; ${p.description}`).join('\n');
        const response = await fetch(process.env.AI_PROVIDER_URL, { method: 'POST', headers: { Authorization: `Bearer ${process.env.AI_PROVIDER_API_KEY}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ model: process.env.AI_MODEL, messages: [{ role: 'system', content: `You are Brew & Bloom customer care. Only use this verified menu and setting data. If unknown, say you do not know. Never claim to refund, cancel, or change an order.\n${context}\nDelivery fee: ₹${db.settings.deliveryFee}` }, { role: 'user', content: question }], temperature: 0.2 }) });
        const payload = await response.json(); if (response.ok && payload.choices?.[0]?.message?.content) answer = cleanText(payload.choices[0].message.content, 3000);
      } catch (error) { console.warn('AI provider unavailable; using verified local response:', error.message); }
    }
    return json(res, 200, { answer });
  }

  return json(res, 404, { error: 'API endpoint not found.' });
}

const MIME = { '.html': 'text/html; charset=utf-8', '.css': 'text/css; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.json': 'application/json; charset=utf-8', '.svg': 'image/svg+xml', '.png': 'image/png', '.jpg': 'image/jpeg', '.jpeg': 'image/jpeg', '.webp': 'image/webp', '.ico': 'image/x-icon', '.txt': 'text/plain; charset=utf-8', '.webmanifest': 'application/manifest+json' };
const ORIGINAL_HTML = new Set(['index.html', 'menu.html', 'about.html', 'contact.html']);
function injectAddons(html) {
  if (html.includes('/js/addons.js')) return html;
  html = html.replace('</head>', '    <link rel="stylesheet" href="/addons.css">\n</head>');
  html = html.replace('</body>', '    <script defer src="/js/addons.js"></script>\n</body>');
  return html;
}
async function handle(req, res) {
  try {
    const url = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
    if (url.pathname.startsWith('/api/')) return await api(req, res, url);
    if (url.pathname === '/auth/google') {
      if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return json(res, 503, { error: 'Google sign-in is not configured. Add Google OAuth credentials and set the authorized redirect URI.' });
      const state = crypto.randomBytes(24).toString('hex');
      setCookie(res, 'cbb_oauth_state', state, { maxAge: 600 });
      const redirectUri = `${process.env.APP_BASE_URL || `http://localhost:${activePort}`}/auth/google/callback`;
      const target = new URL('https://accounts.google.com/o/oauth2/v2/auth');
      target.searchParams.set('client_id', process.env.GOOGLE_CLIENT_ID);
      target.searchParams.set('redirect_uri', redirectUri);
      target.searchParams.set('response_type', 'code');
      target.searchParams.set('scope', 'openid email profile');
      target.searchParams.set('state', state);
      target.searchParams.set('prompt', 'select_account');
      res.writeHead(302, { Location: target.toString(), 'Cache-Control': 'no-store' }); return res.end();
    }
    if (url.pathname === '/auth/google/callback') {
      if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) return json(res, 503, { error: 'Google sign-in is not configured.' });
      const stateCookie = parseCookies(req.headers.cookie || '').cbb_oauth_state;
      const stateQuery = url.searchParams.get('state') || '';
      if (!stateCookie || !stateQuery || stateCookie !== stateQuery || !url.searchParams.get('code')) return json(res, 400, { error: 'Google sign-in could not be verified. Please restart sign-in.' });
      setCookie(res, 'cbb_oauth_state', '', { maxAge: 0 });
      const redirectUri = `${process.env.APP_BASE_URL || `http://localhost:${activePort}`}/auth/google/callback`;
      const tokenResponse = await fetch('https://oauth2.googleapis.com/token', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ code: url.searchParams.get('code'), client_id: process.env.GOOGLE_CLIENT_ID, client_secret: process.env.GOOGLE_CLIENT_SECRET, redirect_uri: redirectUri, grant_type: 'authorization_code' }) });
      const tokens = await tokenResponse.json().catch(() => ({}));
      if (!tokenResponse.ok || !tokens.access_token) return json(res, 502, { error: 'Google could not complete sign-in.' });
      const infoResponse = await fetch('https://www.googleapis.com/oauth2/v3/userinfo', { headers: { Authorization: `Bearer ${tokens.access_token}` } });
      const info = await infoResponse.json().catch(() => ({}));
      if (!infoResponse.ok || !info.email || info.email_verified !== true) return json(res, 403, { error: 'A verified Google email is required.' });
      const email = emailNorm(info.email); let account = db.users.find(u => u.email === email);
      if (account && account.role !== 'customer') return json(res, 403, { error: 'This Google account is associated with a non-customer account.' });
      if (!account) { account = { id: uid('usr_'), name: cleanText(info.name || 'Customer', 100), email, mobile: '', role: 'customer', googleSubject: cleanText(info.sub, 150), partnerApproved: false, loyaltyPoints: 0, createdAt: now() }; db.users.push(account); saveDb(); }
      issueSession(res, account); res.writeHead(302, { Location: '/account.html', 'Cache-Control': 'no-store' }); return res.end();
    }
    if (req.method !== 'GET' && req.method !== 'HEAD') return json(res, 405, { error: 'Method not allowed.' });
    let requestPath = decodeURIComponent(url.pathname);
    if (requestPath === '/') requestPath = '/index.html';
    if (requestPath.endsWith('/')) requestPath += 'index.html';
    const filePath = path.resolve(ROOT, '.' + requestPath);
    const relativePath = path.relative(ROOT, filePath).replace(/\\/g, '/');
    if (!filePath.startsWith(ROOT + path.sep) && filePath !== ROOT) return json(res, 403, { error: 'Forbidden.' });
    if (relativePath.startsWith('.') || relativePath.startsWith('data/') || relativePath === 'server.js' || relativePath.startsWith('node_modules/') || relativePath.startsWith('.git/')) return json(res, 404, { error: 'Not found.' });
    if (!fs.existsSync(filePath) || !fs.statSync(filePath).isFile()) {
      const notFound = path.join(ROOT, '404.html');
      if (fs.existsSync(notFound)) { res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' }); return res.end(fs.readFileSync(notFound)); }
      return json(res, 404, { error: 'Page not found.' });
    }
    const ext = path.extname(filePath).toLowerCase();
    res.setHeader('Content-Type', MIME[ext] || 'application/octet-stream');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    res.setHeader('X-Frame-Options', 'SAMEORIGIN');
    if (ext === '.html') {
      res.setHeader('Cache-Control', 'no-store');
      let html = fs.readFileSync(filePath, 'utf8');
      if (ORIGINAL_HTML.has(path.basename(filePath))) html = injectAddons(html);
      return res.end(html);
    }
    res.setHeader('Cache-Control', ext === '.css' || ext === '.js' ? 'no-cache' : 'public, max-age=3600');
    if (req.method === 'HEAD') return res.end();
    fs.createReadStream(filePath).pipe(res);
  } catch (error) {
    console.error(error);
    if (!res.headersSent) json(res, error.status || 500, { error: error.status ? error.message : 'An unexpected server error occurred.' });
    else res.end();
  }
}

const server = http.createServer(handle);
let activePort = PORT;
let portAttempts = 0;
function listen() {
  server.once('error', error => {
    if (error.code === 'EADDRINUSE' && portAttempts < 10) {
      portAttempts += 1; activePort = PORT + portAttempts;
      console.warn(`Port ${activePort - 1} is already in use. Trying ${activePort}…`);
      listen();
    } else { console.error('Could not start the Brew & Bloom server:', error.message); process.exit(1); }
  });
  server.listen(activePort, () => {
    console.log(`\nBrew & Bloom is running at http://localhost:${activePort}`);
    console.log(`Admin sign-in: ${adminEmail}`);
    console.log('Original HTML and style.css remain untouched. Add-ons are served separately.');
    if (!process.env.RAZORPAY_KEY_ID || !process.env.RAZORPAY_KEY_SECRET) console.log('Online payments: disabled until Razorpay test keys are configured.');
    if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) console.log('Google OAuth: not configured; email/password login is available.');
  });
}
listen();
