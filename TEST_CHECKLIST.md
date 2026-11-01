# Manual Test Checklist

## Start-up
- [ ] `npm.cmd run check` passes.
- [ ] `npm.cmd run dev` starts and prints the local URL.
- [ ] If port 3000 is occupied, server selects the next free port.
- [ ] `GET /api/health` returns `{ "ok": true }`.
- [ ] Original home, menu, about and contact pages render.
- [ ] Original `style.css` hash matches the source archive.

## Catalogue and cart
- [ ] All original menu sections / items appear.
- [ ] Search and category filters work.
- [ ] Add-to-cart buttons update the cart count.
- [ ] Quantity, remove and subtotal work on cart page.
- [ ] Unavailable products cannot be added.

## Accounts
- [ ] Customer can register and sign in.
- [ ] Invalid password is rejected.
- [ ] Customer can sign out.
- [ ] Development OTP can be requested and verified; verify terminal output.
- [ ] Google OAuth remains unavailable until valid credentials and redirect URI are configured.

## Ordering and payment
- [ ] Customer can place a takeaway or dine-in pay-at-café order.
- [ ] Delivery requires a complete address and Razorpay online payment selection.
- [ ] Order total is computed on server from current prices.
- [ ] Welcome coupon is applied only if eligible.
- [ ] Razorpay test order, signature verification, captured/authorized status and webhook deduplication are tested with provider test credentials.
- [ ] Do not use live credentials during development.

## Partner, admin and support
- [ ] Partner application creates a pending account/application.
- [ ] Pending partner cannot log in for delivery work.
- [ ] Admin approves/rejects application.
- [ ] Admin assigns an approved partner to a delivery order.
- [ ] Partner sees only assigned deliveries.
- [ ] Delivery completion requires the customer's delivery OTP.
- [ ] Customer creates a support ticket; admin can reply.
- [ ] Admin can add/disable/archive products, view reservations and add inventory.

## Production readiness blockers
- [ ] PostgreSQL implementation and access policies replace JSON storage.
- [ ] Transactional inventory/stock handling, POS and kitchen workflows exist and are tested.
- [ ] SMS/email/push provider and templates are implemented and tested.
- [ ] Legal policies, tax, hours, contact data and allergen data are verified.
- [ ] HTTPS, logging, monitoring, backup and restore are configured.
- [ ] Independent security and accessibility reviews are complete.
