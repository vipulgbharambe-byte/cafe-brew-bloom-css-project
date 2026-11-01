# Security Notes

- Original HTML and CSS files are preserved; new functionality is separate.
- Passwords are hashed with Node's built-in scrypt and per-password random salts.
- Authentication uses signed, HTTP-only, SameSite=Lax cookies and server-side session records.
- State-changing JSON requests require a custom same-origin request header and same-origin check.
- Basic per-IP rate limits protect login, registration, OTP, partner application and chat routes.
- Customer order and ticket reads are owner-scoped. Delivery partner reads are scoped to assigned orders.
- Only the seeded admin role can use `/api/admin/*`; customer registration cannot choose a role.
- Prices are recalculated on the server from the product catalogue when an order is created.
- Razorpay secrets stay server-side; checkout signature and webhook signature are verified with HMAC.
- Sensitive application data is not served as a static file; `.env`, `server.js`, dotfiles, `data/` and `.git/` paths are blocked.

## Required before production

This build's JSON data store and single-admin authorization are not production-grade for a real public multi-user business. Replace them with a managed PostgreSQL database and transactional data layer, table-level access policies, a robust session store, stronger rate limiting/WAF, secrets manager, HTTPS, structured audit retention, automated backups, restore drills, dependency scanning, penetration testing, and a full review of applicable Indian privacy / consumer / tax requirements.

Change the local admin password and session secret. Do not use the development OTP mode in production. Do not activate Razorpay live keys until payment and webhook test cases pass. Restrict access to the machine and its data directory during local pilot use.
