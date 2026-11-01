# Brew & Bloom — Original Website + E-commerce Add-ons

This project starts from the uploaded `cafe-brew-bloom-css-project` source. The original files below are preserved without edits:

- `index.html`
- `menu.html`
- `about.html`
- `contact.html`
- `style.css`

The server injects the add-on CSS and JavaScript into the four original HTML pages at request time. It does not rewrite those original files. The add-on interface uses the same warm cream, coffee-brown and caramel palette, with separate namespaced styles in `addons.css`.

## Requirements

- Windows 10/11, macOS or Linux
- Node.js 20.9 or newer (Node.js 22 or 24 LTS is recommended for a deployment environment)
- A modern browser

The core application uses Node.js built-in modules only. `npm install` does not need to download third-party packages.

## Run on Windows / PowerShell

1. Extract this ZIP to a normal project folder, for example `D:\vipul projects\cafe-brew-bloom`.
2. Open that folder in VS Code. It must be the folder containing `package.json` and `server.js`.
3. Open **Terminal → New Terminal**.
4. Create the local configuration file:

   ```powershell
   Copy-Item .env.example .env
   ```

   If `.env` already exists, do not overwrite it. Open it with `notepad .env` and review the settings instead.

5. Install / generate the npm lock file:

   ```powershell
   npm.cmd install
   ```

6. Start the website:

   ```powershell
   npm.cmd run dev
   ```

7. Open the exact `http://localhost:PORT` address printed in the terminal. If port 3000 is busy, the server automatically tries 3001, 3002, and so on.

Keep the terminal open while using the site. Press `Ctrl + C` to stop the server.

## Local administrator sign-in

The development defaults in `.env.example` are:

- URL: `http://localhost:3000/admin.html` (use the port printed by your server)
- Email: `admin@cafebrewbloom.local`
- Password: `ChangeThisAdminPassword123!`

Change `ADMIN_PASSWORD` in `.env` before sharing the computer or deploying. The app creates this administrator on the first run and saves application records in `data/app-data.json`. Changing the environment password later does not automatically change an already-created account password; use a controlled password-management workflow before production.

## What is included

### Original customer website

- Original Home, Menu, About and Contact pages and original `style.css` are preserved.
- Product catalogue is seeded from the original menu HTML (32 listed menu products) plus the Chocolate Shake already featured on the original homepage.
- Original menu cards and visual layout stay in place. Add-to-cart controls and search/filter controls are added separately.
- Cart count, cart page, customer account page, checkout page and order history.
- Customer registration and email/password sign-in.
- Google OAuth flow is implemented but disabled until Google credentials and the exact redirect URI are configured.
- Mobile OTP flow works only as a local development test: the OTP is printed in the server terminal and shown in the development response. It is intentionally disabled for production until a real SMS provider is integrated.
- First-order coupon `WELCOME10` is configurable in the admin settings.
- Floating customer-care chatbot uses verified catalogue/business settings and gives a safe fallback response. An optional OpenAI-compatible chat endpoint can be configured; only the user's question and current menu/settings context are sent to that provider.

### Operations / admin

- Admin overview, order status updates, product creation/availability/archive, partner application approval, delivery assignment, customer support replies, reservation list, inventory list/add, configuration settings, user list and audit log.
- Delivery partner application, approval status and assigned-delivery status updates.
- Delivery completion requires the customer-specific delivery OTP displayed in the customer's order details.
- Customer support ticket creation and history.
- Table reservation request capture (request is not confirmed until staff confirms it).
- Order records and user records persist in a local JSON database.

### Payment

- Razorpay order creation is server-side.
- Checkout signature is verified server-side, then the payment is fetched from Razorpay before the local payment state is updated.
- Webhook signature verification and duplicate event protection are included.
- Refund requests can be initiated from admin for verified Razorpay payments; final refund status is updated from webhook events.
- Online payment is disabled until valid Razorpay test credentials and webhook settings are supplied.
- The demo "Pay at café" option is offered only for takeaway and dine-in. It is not a delivery cash-on-delivery feature.

## Configuration

See `CONFIGURATION_AND_INTEGRATIONS.md` for provider setup, data sharing and production requirements.

Important environment variables:

- `SESSION_SECRET`: long random secret used to sign session cookies.
- `ADMIN_EMAIL`, `ADMIN_PASSWORD`: first local administrator.
- `RAZORPAY_KEY_ID`, `RAZORPAY_KEY_SECRET`, `RAZORPAY_WEBHOOK_SECRET`: Razorpay test integration.
- `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, `APP_BASE_URL`: Google OAuth.
- `AI_PROVIDER_URL`, `AI_PROVIDER_API_KEY`, `AI_MODEL`: optional OpenAI-compatible chatbot provider.

Never commit `.env`, `.env.local` or `data/app-data.json`.

## Important production boundary

This ZIP is an integrated, runnable local application and a working feature foundation. It is **not yet a certified, production-ready multi-user commerce platform**. The current server persists to a local JSON file and is intended for development / a controlled single-instance pilot. Before public commercial launch, migrate data and authorization to managed PostgreSQL with proper row-level policies and backups, configure and test live Razorpay webhooks, configure SMS/email delivery, verify business address/hours/menu/allergen/tax/refund policies, test restore and concurrency, configure HTTPS and monitoring, and complete security review.

Not implemented in this build: full POS billing/receipt printer integration, kitchen display workflow, recipe-based ingredient deduction, purchase orders/supplier settlements, loyalty redemption, membership/gift-card ledger, marketing campaign delivery, multi-branch isolation, full staff granular RBAC, automated email/SMS/push notifications and PDF invoices. These should not be represented to customers as available until implemented and tested.

## Checks

Run JavaScript syntax checks:

```powershell
npm.cmd run check
```

Check the service health endpoint after startup:

```powershell
Invoke-RestMethod http://localhost:3000/api/health
```

Replace `3000` with the actual port printed in the terminal if it changed.
