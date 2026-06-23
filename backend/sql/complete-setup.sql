-- ============================================================
-- payments_app — COMPLETE SUBSCRIPTION/PAYMENTS SCHEMA (run ONCE on a fresh database)
-- Single self-contained file: extensions + plans/subscriptions/payments/payment_history.
-- ============================================================
-- Extensions (required on a fresh project; idempotent)
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- ============================================================================
-- Secure Messenger — SUBSCRIPTION SCHEMA (optional, additive)
-- ============================================================================
-- Run this AFTER messaging-schema.sql. It adds the subscription/billing system:
--   subscription_plans, subscriptions, payments  (+ RLS, grants, helpers)
--   a 30-day trial auto-created for every new user (trigger on auth.users)
--
-- Stripe is OPTIONAL until a user upgrades: new users get a 30-day Premium
-- trial automatically, so the app is fully usable before any Stripe setup.
-- To enable paid upgrades:
--   1. Create your products/prices in Stripe and put the price IDs in
--      subscription_plans.stripe_price_id (UPDATE the rows below, or edit here).
--   2. Deploy the edge functions in ../supabaseEdgeFunctions/ (checkout-session,
--      customer-portal, stripe-webhook) with your Stripe keys.
--   3. Set the Stripe publishable key + endpoints in
--      payments/config/moneyTrackerConfig.js (internal config name kept as-is).
-- ============================================================================

-- Idempotent drops
DROP TRIGGER IF EXISTS trigger_create_trial_subscription ON auth.users;
DROP TRIGGER IF EXISTS trigger_update_subscriptions_updated_at ON subscriptions;
DROP FUNCTION IF EXISTS create_trial_subscription() CASCADE;
DROP FUNCTION IF EXISTS update_subscriptions_updated_at() CASCADE;
DROP FUNCTION IF EXISTS is_free_plan(BIGINT) CASCADE;
DROP FUNCTION IF EXISTS is_on_trial(TEXT, TIMESTAMPTZ) CASCADE;
DROP FUNCTION IF EXISTS get_price_dollars(BIGINT) CASCADE;
DROP FUNCTION IF EXISTS get_subscription_type(BIGINT, TEXT) CASCADE;
DROP FUNCTION IF EXISTS is_recurring_billing_enabled(BOOLEAN) CASCADE;
-- H-3: trial-expiry sweep. is_premium_active(UUID) is NOT dropped here — on the shared
-- project the secure_db messages_insert_participant policy depends on it, so a CASCADE
-- drop would tear down that policy. It is maintained via CREATE OR REPLACE below (stable
-- signature + return type, so no DROP is needed).
DROP FUNCTION IF EXISTS expire_overdue_trials() CASCADE;
DROP TABLE IF EXISTS payment_history CASCADE;
DROP TABLE IF EXISTS payments CASCADE;
DROP TABLE IF EXISTS subscriptions CASCADE;
DROP TABLE IF EXISTS subscription_plans CASCADE;

-- ============================================================
-- SUBSCRIPTION SYSTEM
-- ============================================================

CREATE TABLE IF NOT EXISTS subscription_plans (
    id BIGSERIAL PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    description TEXT,  -- Plan description for UI display
    stripe_price_id TEXT UNIQUE,  -- Stripe's price ID (null until you create one)
    price_cents INT NOT NULL,  -- 0 for Free, 999 for $9.99/month
    interval TEXT NOT NULL CHECK (interval IN ('month', 'year')),
    features JSONB DEFAULT '[]',
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Enable RLS but allow all authenticated users to read (public plan data)
ALTER TABLE subscription_plans ENABLE ROW LEVEL SECURITY;

CREATE POLICY subscription_plans_select_all ON subscription_plans
    FOR SELECT TO authenticated USING (true);

CREATE TABLE IF NOT EXISTS subscriptions (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL UNIQUE REFERENCES auth.users(id) ON DELETE CASCADE,
    plan_id BIGINT NOT NULL REFERENCES subscription_plans(id),

    -- Stripe integration (null for Free plan users)
    stripe_customer_id TEXT,
    stripe_subscription_id TEXT UNIQUE,
    stripe_price_id TEXT,

    -- Subscription status (source of truth from Stripe)
    status TEXT NOT NULL DEFAULT 'trial' CHECK (status IN (
        'trial',      -- 30-day trial (new users)
        'active',     -- Active subscription (Free or Premium)
        'past_due',   -- Payment failed
        'canceled',   -- Canceled by user
        'unpaid'      -- Payment failed multiple times
    )),

    -- Billing period (from Stripe, updated by webhook)
    current_period_start TIMESTAMPTZ,
    current_period_end TIMESTAMPTZ,  -- This IS the next billing date!

    -- Trial management
    trial_end TIMESTAMPTZ DEFAULT (NOW() + INTERVAL '30 days'),

    -- Cancellation tracking
    cancel_at_period_end BOOLEAN DEFAULT false,
    canceled_at TIMESTAMPTZ,

    -- Downgrade scheduling (null if no pending change)
    pending_plan_id BIGINT REFERENCES subscription_plans(id),
    pending_change_at TIMESTAMPTZ,  -- When downgrade takes effect (= current_period_end)

    created_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE subscriptions ENABLE ROW LEVEL SECURITY;

CREATE POLICY subscriptions_select_own ON subscriptions
    FOR SELECT USING (auth.uid() = user_id);

CREATE POLICY subscriptions_update_own ON subscriptions
    FOR UPDATE USING (auth.uid() = user_id);

CREATE POLICY subscriptions_insert_own ON subscriptions
    FOR INSERT WITH CHECK (auth.uid() = user_id);

CREATE OR REPLACE FUNCTION update_subscriptions_updated_at()
RETURNS TRIGGER
LANGUAGE plpgsql
SET search_path = public
AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$;

CREATE TRIGGER trigger_update_subscriptions_updated_at
    BEFORE UPDATE ON subscriptions
    FOR EACH ROW
    EXECUTE FUNCTION update_subscriptions_updated_at();

GRANT SELECT ON subscription_plans TO authenticated;
GRANT SELECT, INSERT, UPDATE ON subscriptions TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE subscriptions_id_seq TO authenticated;

CREATE TABLE IF NOT EXISTS payments (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    stripe_payment_intent_id TEXT UNIQUE,
    amount_cents INT NOT NULL,
    currency TEXT DEFAULT 'usd',
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW()
);

ALTER TABLE payments ENABLE ROW LEVEL SECURITY;

CREATE POLICY payments_select_own ON payments
    FOR SELECT USING (auth.uid() = user_id);

GRANT SELECT ON payments TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE payments_id_seq TO authenticated;

-- ============================================================
-- PAYMENT HISTORY (written by the stripe-webhook edge function)
-- ============================================================
-- The stripe-webhook records every invoice payment here via the service role
-- (recordPayment() in edge-functions/stripe-webhook.ts). The subscription UI
-- reads it back (PaymentService.getPaymentHistory + renderPaymentHistory) and
-- the webhook re-reads it by (user_id, stripe_invoice_id) to attach the new
-- payment id to its notifications. The legacy `payments` table above lacks
-- stripe_invoice_id, so this separate table is required for those read-backs.
-- NOTE: amount is stored in MAJOR units (dollars/euros). The webhook divides
-- Stripe's integer cents by 100 before writing (e.g. invoice.amount_paid / 100).
CREATE TABLE IF NOT EXISTS payment_history (
    id BIGSERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    subscription_id UUID,  -- webhook writes the user_id here ("user_id is the subscription_id in our schema")
    stripe_payment_intent_id TEXT,
    stripe_charge_id TEXT,
    stripe_invoice_id TEXT,
    amount NUMERIC(12, 2) NOT NULL DEFAULT 0,  -- major units (dollars/euros), NOT cents
    currency TEXT NOT NULL DEFAULT 'usd',
    status TEXT NOT NULL,
    payment_method TEXT,
    payment_date TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    refunded_amount NUMERIC(12, 2) DEFAULT 0,
    refunded_date TIMESTAMPTZ,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Read-back path: webhook filters by (user_id, stripe_invoice_id); UI filters by user_id.
CREATE INDEX IF NOT EXISTS idx_payment_history_user_invoice
    ON payment_history(user_id, stripe_invoice_id);

ALTER TABLE payment_history ENABLE ROW LEVEL SECURITY;

-- The subscription UI reads a user's own payment history.
CREATE POLICY payment_history_select_own ON payment_history
    FOR SELECT USING (auth.uid() = user_id);

-- Writes are performed by the stripe-webhook with the service role (which
-- bypasses RLS), so authenticated users get SELECT only — never INSERT/UPDATE.
GRANT SELECT ON payment_history TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE payment_history_id_seq TO authenticated;

-- ============================================================
-- STRIPE WEBHOOK EVENTS (idempotency / event de-duplication)
-- ============================================================
-- The stripe-webhook records every received event id here BEFORE processing it,
-- via an atomic INSERT ... ON CONFLICT (stripe_event_id) DO NOTHING using the
-- service role. The insert itself is the lock: if a row already existed the
-- webhook short-circuits with 200 and skips reprocessing (Stripe retries deliver
-- the same event id, so this makes handling idempotent). After successful
-- handling the webhook sets processed = true.
--
-- Intentionally MINIMAL: only the event id, type, a processed flag and a
-- timestamp. The full event payload is NOT stored (avoids persisting PII).
-- Service-role only: RLS is enabled and NO grants are issued to `authenticated`
-- (the webhook runs as the service role, which bypasses RLS).
CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    stripe_event_id TEXT PRIMARY KEY,
    type TEXT,
    processed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE stripe_webhook_events ENABLE ROW LEVEL SECURITY;
-- No policies and no grants to `authenticated`: only the service role (which
-- bypasses RLS) may read/write this table.

-- Populate subscription plans (rebranded for Secure Messenger).
-- Set stripe_price_id to your real Stripe price IDs to enable paid upgrades.
INSERT INTO subscription_plans (name, description, stripe_price_id, price_cents, interval, features, is_active)
VALUES
    ('Free', 'Limited access after your trial ends', NULL, 0, 'month', '["Account & contacts", "Upgrade to send encrypted messages"]'::jsonb, true),
    -- stripe_price_id: Stripe test Price (Secure Messenger Premium, £9.99/mo). Replace for prod/live.
    ('Premium', 'Full end-to-end encrypted messaging', 'price_1Tl87aClUqvgxZvpUn4uUrx6', 999, 'month', '["Unlimited E2E encrypted messaging", "Encrypted file attachments", "Multi-device sync", "Priority support"]'::jsonb, true)
ON CONFLICT (name) DO UPDATE SET
    description = EXCLUDED.description,
    price_cents = EXCLUDED.price_cents,
    features = EXCLUDED.features,
    is_active = EXCLUDED.is_active;

-- ============================================================
-- SUBSCRIPTION HELPER FUNCTIONS (Derived Data)
-- ============================================================

-- Check if subscription is on Free plan
CREATE OR REPLACE FUNCTION is_free_plan(sub_plan_id BIGINT)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
BEGIN
    RETURN (SELECT name FROM subscription_plans WHERE id = sub_plan_id) = 'Free';
END;
$$;

-- Check if subscription is on trial
CREATE OR REPLACE FUNCTION is_on_trial(sub_status TEXT, trial_end_date TIMESTAMPTZ)
RETURNS BOOLEAN
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
BEGIN
    RETURN sub_status = 'trial' AND trial_end_date > NOW();
END;
$$;

-- Get plan price in dollars (for display)
CREATE OR REPLACE FUNCTION get_price_dollars(sub_plan_id BIGINT)
RETURNS NUMERIC
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
BEGIN
    RETURN (SELECT price_cents FROM subscription_plans WHERE id = sub_plan_id) / 100.0;
END;
$$;

-- Get subscription type (derived from plan and status)
CREATE OR REPLACE FUNCTION get_subscription_type(sub_plan_id BIGINT, sub_status TEXT)
RETURNS TEXT
LANGUAGE plpgsql
STABLE
SET search_path = public
AS $$
BEGIN
    IF sub_status = 'trial' THEN
        RETURN 'trial';
    ELSIF is_free_plan(sub_plan_id) THEN
        RETURN 'free';
    ELSE
        RETURN 'paid';
    END IF;
END;
$$;

-- Check if recurring billing is enabled (inverse of cancel_at_period_end)
CREATE OR REPLACE FUNCTION is_recurring_billing_enabled(cancel_at_end BOOLEAN)
RETURNS BOOLEAN
LANGUAGE plpgsql
IMMUTABLE
SET search_path = public
AS $$
BEGIN
    RETURN NOT cancel_at_end;
END;
$$;

GRANT EXECUTE ON FUNCTION is_free_plan(BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION is_on_trial(TEXT, TIMESTAMPTZ) TO authenticated;
GRANT EXECUTE ON FUNCTION get_price_dollars(BIGINT) TO authenticated;
GRANT EXECUTE ON FUNCTION get_subscription_type(BIGINT, TEXT) TO authenticated;
GRANT EXECUTE ON FUNCTION is_recurring_billing_enabled(BOOLEAN) TO authenticated;

-- ============================================================
-- AUTO-CREATE TRIAL SUBSCRIPTION ON SIGNUP
-- ============================================================

-- Automatically create a 30-day Premium trial when a user signs up
CREATE OR REPLACE FUNCTION create_trial_subscription()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    premium_plan_id BIGINT;
BEGIN
    -- Get Premium plan ID
    SELECT id INTO premium_plan_id
    FROM subscription_plans
    WHERE name = 'Premium'
    LIMIT 1;

    -- Create trial subscription for new user
    INSERT INTO subscriptions (
        user_id,
        plan_id,
        status,
        trial_end
    ) VALUES (
        NEW.id,
        premium_plan_id,
        'trial',
        NOW() + INTERVAL '30 days'
    );

    RETURN NEW;
END;
$$;

-- Trigger on user creation
DROP TRIGGER IF EXISTS trigger_create_trial_subscription ON auth.users;
CREATE TRIGGER trigger_create_trial_subscription
    AFTER INSERT ON auth.users
    FOR EACH ROW
    EXECUTE FUNCTION create_trial_subscription();

-- ============================================================
-- SERVER-AUTHORITATIVE ENTITLEMENT (PAY-3 / RLS-03)
-- ============================================================
-- Premium entitlement must never be client-writable. The only write paths into
-- `subscriptions` are the SECURITY DEFINER RPCs below (each re-asserts auth.uid()
-- and constrains what may be set), the signup trigger above, and the Stripe edge
-- functions (service role, which bypass RLS + the REVOKE). The client calls these
-- RPCs via DatabaseService.queryRpc(); it never writes `subscriptions` directly.
--
-- On a FRESH install the bundled client already uses the RPCs, so the REVOKE at the
-- bottom is applied immediately. For an EXISTING database, deploy the new client
-- FIRST and run the standalone staged migration backend/sql/apply-entitlement-lockdown.sql.

-- start_trial(): idempotently put the caller's OWN row onto a Premium trial; refuses
-- to re-grant a trial that was already used. Returns JSONB {success, subscription|error}.
CREATE OR REPLACE FUNCTION start_trial()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid        UUID := auth.uid();
    v_premium_id BIGINT;
    v_trial_days INT := 30;   -- matches create_trial_subscription(); no trial_period_days column exists
    v_existing   subscriptions%ROWTYPE;
    v_row        subscriptions%ROWTYPE;
BEGIN
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    SELECT id INTO v_premium_id FROM subscription_plans WHERE name = 'Premium' LIMIT 1;
    IF v_premium_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Premium plan not found');
    END IF;

    SELECT * INTO v_existing FROM subscriptions WHERE user_id = v_uid;
    IF FOUND THEN
        IF v_existing.status = 'trial' THEN
            RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_existing));
        END IF;
        -- Any non-trial existing row means the trial was already consumed: do not re-grant.
        RETURN jsonb_build_object('success', false, 'error', 'trial already used');
    END IF;

    INSERT INTO subscriptions (user_id, plan_id, status, trial_end)
    VALUES (v_uid, v_premium_id, 'trial', NOW() + (v_trial_days || ' days')::interval)
    RETURNING * INTO v_row;

    RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

-- downgrade_to_free(): put the caller's OWN row onto the Free plan, status 'active',
-- clearing all Stripe/trial/cancellation/pending fields. Used by trial-expiry +
-- cancel-to-Free. Does NOT cancel a live Stripe subscription (that is the update-
-- subscription edge function's job). Returns JSONB {success, subscription|error}.
CREATE OR REPLACE FUNCTION downgrade_to_free()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid     UUID := auth.uid();
    v_free_id BIGINT;
    v_row     subscriptions%ROWTYPE;
BEGIN
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    SELECT id INTO v_free_id FROM subscription_plans WHERE name = 'Free' LIMIT 1;
    IF v_free_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Free plan not found');
    END IF;

    UPDATE subscriptions SET
        plan_id                = v_free_id,
        status                 = 'active',
        trial_end              = NULL,
        stripe_customer_id     = NULL,
        stripe_subscription_id = NULL,
        stripe_price_id        = NULL,
        current_period_start   = NULL,
        current_period_end     = NULL,
        cancel_at_period_end   = false,
        canceled_at            = NULL,
        pending_plan_id        = NULL,
        pending_change_at      = NULL
    WHERE user_id = v_uid
    RETURNING * INTO v_row;

    IF NOT FOUND THEN
        INSERT INTO subscriptions (user_id, plan_id, status, trial_end)
        VALUES (v_uid, v_free_id, 'active', NULL)
        RETURNING * INTO v_row;
    END IF;

    RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

-- ensure_subscription(): guarantee the caller HAS a row (Free/active default — never a
-- trial), so the client never needs a direct INSERT. No-op if the signup trigger fired.
CREATE OR REPLACE FUNCTION ensure_subscription()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid     UUID := auth.uid();
    v_free_id BIGINT;
    v_row     subscriptions%ROWTYPE;
BEGIN
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    SELECT * INTO v_row FROM subscriptions WHERE user_id = v_uid;
    IF FOUND THEN
        RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));
    END IF;

    SELECT id INTO v_free_id FROM subscription_plans WHERE name = 'Free' LIMIT 1;
    IF v_free_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Free plan not found');
    END IF;

    INSERT INTO subscriptions (user_id, plan_id, status, trial_end)
    VALUES (v_uid, v_free_id, 'active', NULL)
    RETURNING * INTO v_row;

    RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));
EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

GRANT EXECUTE ON FUNCTION start_trial() TO authenticated;
GRANT EXECUTE ON FUNCTION downgrade_to_free() TO authenticated;
GRANT EXECUTE ON FUNCTION ensure_subscription() TO authenticated;

-- Defense-in-depth: keep the own-row WITH CHECK even though the grants are revoked.
DROP POLICY IF EXISTS subscriptions_update_own ON subscriptions;
CREATE POLICY subscriptions_update_own ON subscriptions
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS subscriptions_insert_own ON subscriptions;
CREATE POLICY subscriptions_insert_own ON subscriptions
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- LOCKDOWN: clients can read but never write `subscriptions`. (Fresh installs ship the
-- RPC-based client, so this is applied immediately. For an existing DB, run this only
-- AFTER the new client is deployed — see backend/sql/apply-entitlement-lockdown.sql.)
REVOKE INSERT, UPDATE ON subscriptions FROM authenticated;
REVOKE USAGE, SELECT ON SEQUENCE subscriptions_id_seq FROM authenticated;

-- ============================================================
-- SERVER-AUTHORITATIVE PREMIUM ENTITLEMENT PREDICATE (audit H-3)
-- ============================================================
-- The single source of truth for "is this user entitled to Premium RIGHT NOW".
-- Computed from subscriptions + subscription_plans — NEVER from `status` alone:
--   premium == (status='active' AND plan=Premium)
--           OR (status='trial'  AND trial_end > NOW())
-- An EXPIRED trial (trial_end <= NOW()) is treated as NOT premium here, so the gate
-- is correct even BEFORE the pg_cron sweep below flips the stale row to Free. This
-- closes the "keep Premium forever by never running the client downgrade" bypass:
-- the only thing the client could skip was downgrade_to_free(); this predicate no
-- longer trusts the un-swept `status='trial'`.
--
-- SECURITY DEFINER so the messages-INSERT RLS gate (secure_db) can evaluate it
-- regardless of the subscriptions row's own RLS, and so it works for ANY caller path.
-- It only ever reads ONE row (the passed uid) and returns a boolean — it leaks no
-- other user's data. search_path is pinned. The caller (RLS WITH CHECK) always
-- passes auth.uid(), so the answer is scoped to the acting user.
CREATE OR REPLACE FUNCTION is_premium_active(p_uid UUID)
RETURNS BOOLEAN
LANGUAGE sql
STABLE
SECURITY DEFINER
SET search_path = public
AS $$
    SELECT EXISTS (
        SELECT 1
        FROM subscriptions s
        JOIN subscription_plans p ON p.id = s.plan_id
        WHERE s.user_id = p_uid
          AND (
                (s.status = 'active' AND p.name = 'Premium')
             OR (s.status = 'trial'  AND s.trial_end IS NOT NULL AND s.trial_end > NOW())
          )
    );
$$;

-- Callable by authenticated users (the client also uses it to render entitlement
-- truthfully) and by the messages-INSERT RLS gate. No write access.
GRANT EXECUTE ON FUNCTION is_premium_active(UUID) TO authenticated;

-- ============================================================
-- TRIAL EXPIRY SWEEP (audit H-3) — server-side, NOT client-driven
-- ============================================================
-- Flip every expired trial to Free/active. This is the server replacement for the
-- old client-only downgrade_to_free() path. is_premium_active() above already treats
-- an expired trial as non-premium, so enforcement is correct even if this sweep has
-- not yet run — but the sweep keeps the stored rows honest (and the UI accurate).
-- Idempotent: only touches rows that are still status='trial' with a past trial_end.
CREATE OR REPLACE FUNCTION expire_overdue_trials()
RETURNS INTEGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_free_id BIGINT;
    v_count   INTEGER;
BEGIN
    SELECT id INTO v_free_id FROM subscription_plans WHERE name = 'Free' LIMIT 1;
    IF v_free_id IS NULL THEN
        RAISE LOG 'expire_overdue_trials: Free plan not found; skipping';
        RETURN 0;
    END IF;

    UPDATE subscriptions SET
        plan_id   = v_free_id,
        status    = 'active',
        trial_end = NULL
    WHERE status = 'trial'
      AND trial_end IS NOT NULL
      AND trial_end < NOW();

    GET DIAGNOSTICS v_count = ROW_COUNT;
    RETURN v_count;
END;
$$;

-- The sweep runs as the service role (via pg_cron) — do NOT grant it to `authenticated`
-- (a client must never be able to mass-mutate other users' subscription rows).
REVOKE ALL ON FUNCTION expire_overdue_trials() FROM PUBLIC;

-- Schedule the sweep hourly via pg_cron IF the extension is available. pg_cron is a
-- superuser-installed extension; on Supabase enable it once in the Dashboard
-- (Database > Extensions > pg_cron). If it is not present this block is a safe no-op
-- and the DEPLOY note below documents enabling it. Even without the cron, the
-- is_premium_active() predicate already denies expired trials, so revenue is protected.
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        -- cron.schedule is idempotent on the job NAME (newer pg_cron upserts; older
        -- ones error on duplicate, which we swallow so re-running this file is safe).
        BEGIN
            PERFORM cron.schedule(
                'expire-overdue-trials',
                '0 * * * *',               -- top of every hour
                $cron$SELECT public.expire_overdue_trials();$cron$
            );
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'pg_cron present but scheduling expire-overdue-trials failed (likely already scheduled): %', SQLERRM;
        END;
    ELSE
        RAISE NOTICE 'pg_cron not installed: trial-expiry sweep NOT scheduled. is_premium_active() still denies expired trials. Enable pg_cron (Dashboard > Database > Extensions) then re-run this file or call cron.schedule manually.';
    END IF;
END $$;
