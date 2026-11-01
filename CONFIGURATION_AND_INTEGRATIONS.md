# Configuration & Integrations

## 1. Local server and storage

The application uses Node.js built-in HTTP, crypto, filesystem and fetch APIs. It has no external npm runtime dependencies. Local records are written to `data/app-data.json`; the initial product catalogue is in `data/products.json`.

This JSON persistence is for local development and a controlled single-process pilot only. It is not a substitute for PostgreSQL transactions, row-level security, multi-instance coordination or managed backups.

## 2. Razorpay

Required: a Razorpay account and API credentials. Start with test-mode credentials.

Set in `.env`:

```env
RAZORPAY_KEY_ID=rzp_test_...
RAZORPAY_KEY_SECRET=...
RAZORPAY_WEBHOOK_SECRET=...
```

Set the webhook URL to `https://YOUR-DOMAIN/api/payments/razorpay/webhook` and subscribe to at least `payment.captured`, `payment.failed`, `refund.processed` and `refund.failed`. Configure the same webhook secret in `.env`.

The server creates Razorpay orders and verifies checkout signatures server-side. Never put `RAZORPAY_KEY_SECRET` or `RAZORPAY_WEBHOOK_SECRET` in browser JavaScript. Test success, failure, webhook retries, duplicate events, partial refunds and refund delays in test mode before live activation.

Provider fees and eligibility depend on your Razorpay agreement and account; check Razorpay's current official dashboard/docs rather than assuming a fixed rate.

## 3. Google OAuth

Set `GOOGLE_CLIENT_ID` and `GOOGLE_CLIENT_SECRET` in `.env`. Set `APP_BASE_URL` to the exact public origin used by your site. Add this exact Authorized redirect URI to the Google OAuth client:

`https://YOUR-DOMAIN/auth/google/callback`

For local testing, use `http://localhost:3000/auth/google/callback` (or the port configured in `.env`). If the server falls back to another port, update `APP_BASE_URL` and the redirect URI to match. Google requires a valid consent-screen / OAuth client configuration. Do not expose the client secret to the browser.

## 4. Mobile OTP

The current implementation supports a development-only OTP: the server prints the code to its terminal and the account page displays the development code. The production endpoint fails closed rather than pretending an SMS was sent. A verified SMS provider (for example, an Indian transactional SMS provider) and its approved template / sender configuration must be integrated before production OTP sign-in.

## 5. AI chatbot (optional)

The chatbot works without an AI vendor using a deterministic FAQ / catalogue lookup. For an OpenAI-compatible endpoint, configure:

```env
AI_PROVIDER_URL=https://YOUR-PROVIDER/v1/chat/completions
AI_PROVIDER_API_KEY=...
AI_MODEL=YOUR_MODEL_NAME
```

When configured, the server sends the current product list / basic delivery fee context and the customer's submitted chat question. Do not send order history, payment information, password, OTP or identity documents. Provider privacy, retention and pricing depend on the selected provider and account. Verify those terms before enabling it.

## 6. Email, SMS, push and notifications

Automated email, SMS and web-push delivery are not included in this build. The current support ticket and order states are visible in the application; no email/SMS notification should be advertised as operational. Integrate a provider, templates, consent handling, retry queue and delivery monitoring before launch.

## 7. Business settings requiring owner verification

Admin settings include delivery fee and a configurable tax rate. Defaults are development placeholders: delivery fee ₹30 and tax rate 0%. Verify actual delivery fees, service zones, opening hours, reservation capacity, cancellation/refund rules, GST treatment, legal business name, address, telephone, menu prices, ingredients and allergens with the café owner/accountant. The original About/Contact HTML includes its original contact/location text and has not been edited; validate that text before public use.
