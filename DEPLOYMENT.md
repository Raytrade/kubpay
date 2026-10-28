# KubPay deployment runbook

## Deployment target

The repository includes a Docker image and Railway configuration. These files make the service buildable; they do not create a Railway project, provision PostgreSQL, or configure secrets automatically.

## Required server environment

Set these only in the hosting provider's server-side variable manager:

- `PORT`: supplied by the platform (the app defaults to `8080`).
- `DATABASE_URL`: PostgreSQL connection URL; use TLS for hosted databases.
- `JWT_SECRET`: a long, randomly generated secret. Do not commit it or paste it into chat.
- `PAYSTACK_SECRET_KEY`: leave unset or use a Paystack test key until sandbox verification is complete.
- `PAYOUT_REQUIRE_APPROVAL=true`
- `MAX_TRANSFER_KOBO=5000000` (₦50,000 per transfer)
- `DAILY_TRANSFER_KOBO=5000000000` (₦50,000,000 daily aggregate ceiling; this is not a founder balance).

Do not enable live Paystack transfers until database migrations, founder authorization, webhook signature verification, idempotency, reconciliation, and test-mode transfers have been reviewed end to end.

## Database setup

The service requires an existing PostgreSQL database and exits at startup if it cannot connect. The current service does not automatically execute migrations on startup.

1. Create a PostgreSQL database with persistent storage and TLS.
2. Apply `migrations/001_init.sql` once using a trusted SQL client or the hosting provider's database console.
3. Confirm the migration completed before deploying the service.
4. Configure `DATABASE_URL` and the other server variables.
5. Deploy the service and verify:
   - `GET /health` returns HTTP 200 with service `kubpay`.
   - `GET /ready` returns HTTP 200 only when PostgreSQL is reachable.
6. Test login and protected read-only routes with a dedicated test account and non-production data.

Never paste database credentials, JWT secrets, or Paystack secret keys into source files, GitHub issues, or chat.

## Important integration status

A successful Go CI run confirms formatting, module integrity, tests, vet, and compilation only. It does not confirm that a live server or database exists.

Before connecting the WhityRay Digital Twin, verify the actual KubPay HTTPS origin and the exact API request/response schemas. Keep the Twin's `FINANCE_ENABLE_PAYOUTS=false` until that test is complete. The Twin bridge must never treat an HTTP 202/201 acceptance response as proof that money was transferred.

Incoming income credits are not complete until a provider-verified event is validated against reference, amount, and currency and then posted to the ledger exactly once. Do not manually credit a balance based on a browser redirect or client-supplied claim.
