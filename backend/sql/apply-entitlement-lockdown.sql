-- ============================================================================
-- ENTITLEMENT LOCKDOWN — server-authoritative Premium entitlement (audit PAY-3 / RLS-03)
-- Idempotent, non-destructive. Closes the hole where an authenticated user could
-- self-grant Premium by a direct `subscriptions` UPDATE/INSERT (RLS allowed it via
-- subscriptions_update_own / subscriptions_insert_own) or by replaying ?upgrade=success.
--
-- After this migration, the ONLY write paths into `subscriptions` are:
--   1. SECURITY DEFINER RPCs below (start_trial / downgrade_to_free / ensure_subscription),
--      each of which re-asserts auth.uid() and constrains WHAT the caller may set.
--   2. The signup trigger create_trial_subscription() (SECURITY DEFINER, already present).
--   3. The Stripe edge functions (checkout-session / update-subscription / stripe-webhook),
--      which connect with the SERVICE ROLE key and therefore BYPASS RLS *and* the REVOKE.
--
-- ⚠ STAGED DEPLOY — DO NOT run the REVOKE block (Stage C, bottom of this file) until
--   the new client (which calls the RPCs instead of writing `subscriptions` directly)
--   is fully deployed. The CREATE OR REPLACE RPCs + GRANTs (Stage A) are safe to run
--   first and at any time; they are additive. See the runbook at the end.
--
-- Safe to re-run. Mirrors backend/sql/complete-setup.sql (canonical) and the
-- money_tracker installer (database/setup/fresh-install-complete.sql).
-- ============================================================================

-- ===========================================================================
-- STAGE A — SECURITY DEFINER RPCs + GRANTs (additive; deploy FIRST, with/ before client)
-- ===========================================================================
BEGIN;

-- ---------------------------------------------------------------------------
-- start_trial() — idempotently put the CALLER'S OWN row onto a Premium trial.
-- Anti-abuse: refuses if the caller has already had a trial (or is/was paid),
-- so a user cannot repeatedly re-trial to keep free Premium forever.
-- Returns the resulting subscription row as JSONB ({success:false,error:...} on refusal).
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION start_trial()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid           UUID := auth.uid();
    v_premium_id    BIGINT;
    v_trial_days    INT := 30;   -- matches create_trial_subscription() trigger; subscription_plans has no trial_period_days column
    v_existing      subscriptions%ROWTYPE;
    v_row           subscriptions%ROWTYPE;
BEGIN
    -- Must be an authenticated end-user. Service-role callers have NULL auth.uid()
    -- and should write subscriptions directly (they have their own trusted paths),
    -- so reject NULL here to avoid an unscoped self-grant.
    IF v_uid IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'not authenticated');
    END IF;

    SELECT id INTO v_premium_id FROM subscription_plans WHERE name = 'Premium' LIMIT 1;
    IF v_premium_id IS NULL THEN
        RETURN jsonb_build_object('success', false, 'error', 'Premium plan not found');
    END IF;

    SELECT * INTO v_existing FROM subscriptions WHERE user_id = v_uid;

    IF FOUND THEN
        -- Idempotent: if they are ALREADY on a live trial, just return it.
        IF v_existing.status = 'trial' THEN
            RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_existing));
        END IF;

        -- Anti-reuse: a row that is not currently 'trial' means the trial was already
        -- consumed (downgraded to Free, paid/active, canceled, etc). Do NOT re-grant.
        RETURN jsonb_build_object('success', false, 'error', 'trial already used');
    END IF;

    -- No row yet (signup trigger did not fire — the original fallback case). Create one.
    INSERT INTO subscriptions (user_id, plan_id, status, trial_end)
    VALUES (v_uid, v_premium_id, 'trial', NOW() + (v_trial_days || ' days')::interval)
    RETURNING * INTO v_row;

    RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));

EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

GRANT EXECUTE ON FUNCTION start_trial() TO authenticated;

-- ---------------------------------------------------------------------------
-- downgrade_to_free() — put the CALLER'S OWN row onto the Free plan, status 'active',
-- clearing all Stripe/trial/cancellation/pending fields. Used by trial-expiry
-- auto-downgrade and by a client-initiated cancel-to-Free. Idempotent.
-- Does NOT touch Stripe — cancelling a live Stripe subscription remains the job of
-- the update-subscription edge function (service role). This only fixes local entitlement.
-- ---------------------------------------------------------------------------
CREATE OR REPLACE FUNCTION downgrade_to_free()
RETURNS JSONB
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
    v_uid       UUID := auth.uid();
    v_free_id   BIGINT;
    v_row       subscriptions%ROWTYPE;
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
        -- No row yet: create the Free row directly so the caller ends up entitled-as-Free.
        INSERT INTO subscriptions (user_id, plan_id, status, trial_end)
        VALUES (v_uid, v_free_id, 'active', NULL)
        RETURNING * INTO v_row;
    END IF;

    RETURN jsonb_build_object('success', true, 'subscription', to_jsonb(v_row));

EXCEPTION WHEN OTHERS THEN
    RETURN jsonb_build_object('success', false, 'error', SQLERRM);
END;
$$;

GRANT EXECUTE ON FUNCTION downgrade_to_free() TO authenticated;

-- ---------------------------------------------------------------------------
-- ensure_subscription() — guarantee the caller HAS a row, without granting Premium.
-- If the signup trigger fired, this is a no-op returning the existing row. If it did
-- NOT (edge case), it creates a Free/active row (the safe default — NOT a trial, so it
-- can't be used to self-grant Premium). Lets the client drop its direct INSERT entirely.
-- ---------------------------------------------------------------------------
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

GRANT EXECUTE ON FUNCTION ensure_subscription() TO authenticated;

COMMIT;

-- ===========================================================================
-- STAGE C — THE REVOKE (run LAST, only after the RPC-calling client is deployed)
-- ===========================================================================
-- Once no client writes `subscriptions` directly, remove the client's INSERT/UPDATE
-- grants and the permissive RLS write policies. SELECT stays so the UI can still read
-- the user's own row. The SECURITY DEFINER RPCs + service-role edge functions are
-- unaffected (DEFINER runs as the function owner; service role bypasses RLS).
--
-- To stage: KEEP the block below commented in the canonical installer until cutover,
-- then run it (or run apply-entitlement-lockdown.sql in full once the client is live).
-- It is written idempotently so re-running is harmless.
BEGIN;

-- Defense-in-depth: tighten the (soon-to-be-unreachable) write policies with a
-- WITH CHECK so that even if a grant is ever re-added by mistake, a user can only
-- ever target their OWN row. (REVOKE below is the real lock; this is belt-and-braces.)
DROP POLICY IF EXISTS subscriptions_update_own ON subscriptions;
CREATE POLICY subscriptions_update_own ON subscriptions
    FOR UPDATE USING (auth.uid() = user_id)
    WITH CHECK (auth.uid() = user_id);

DROP POLICY IF EXISTS subscriptions_insert_own ON subscriptions;
CREATE POLICY subscriptions_insert_own ON subscriptions
    FOR INSERT WITH CHECK (auth.uid() = user_id);

-- The actual lockdown: clients can no longer INSERT/UPDATE subscriptions at all.
-- All entitlement writes now flow through the SECURITY DEFINER RPCs above and the
-- service-role edge functions. SELECT is retained.
REVOKE INSERT, UPDATE ON subscriptions FROM authenticated;

-- The sequence grant is only needed for client-side INSERT, which is now gone.
-- (SECURITY DEFINER inserts run as the owner, not `authenticated`.)
REVOKE USAGE, SELECT ON SEQUENCE subscriptions_id_seq FROM authenticated;

COMMIT;
