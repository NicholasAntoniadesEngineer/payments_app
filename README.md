# payments_app — shared payments / subscription (client + backend)

Stripe subscription/billing, shared by **money_tracker** and **messaging_app** over
the one shared Supabase project. Premium gates messaging + attachments; new users
get a 30-day trial on signup (trigger in the backend SQL).

## Contents

### Client (consumed as a git submodule)
- `payments/**` — config, services (Stripe, payment, subscription), controllers
  (upgrade, payment), `views/subscription.html`, module init/utils.
- `shared/utils/{subscriptionGuard,permissionService}.js` — feature-tier gating.

Configure your Stripe **publishable** key + the deployed edge-function endpoint
names in `payments/config/moneyTrackerConfig.js`. The deployed function names are
`checkout-session`, `create-portal-session`, `stripe-webhook`.

### Backend (applied to the shared Supabase project — step 3 of the DB runbook)
- `backend/sql/subscription-schema.sql` — `subscription_plans` / `subscriptions` /
  `payments` + RLS + helper fns + 30-day-trial trigger. Seeds Premium with its
  Stripe `stripe_price_id` (replace for live).
- `backend/edge-functions/` — `checkout-session.ts`, `create-portal-session.ts`,
  `stripe-webhook.ts`. Deploy with secrets `STRIPE_SECRET_KEY` (+ `STRIPE_WEBHOOK_SECRET`
  for the webhook).

## Consumption

```bash
git submodule add https://github.com/NicholasAntoniadesEngineer/payments_app lib/payments_app
```
Depends on the shared foundation (`auth_db`) at runtime (`window.SupabaseConfig`,
`window.AuthService`, `window.DatabaseService`).

## DB init order
auth_db → secure_db → **payments** (this) → budget
