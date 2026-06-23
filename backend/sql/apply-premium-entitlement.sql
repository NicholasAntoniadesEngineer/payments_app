-- ============================================================================
-- SERVER-AUTHORITATIVE PREMIUM ENTITLEMENT + TRIAL EXPIRY
-- PAYMENTS-SIDE migration (run ONCE in the SQL Editor). Idempotent, non-destructive.
-- ============================================================================
-- PRODUCT DECISION: MESSAGING IS FREE; the Premium feature is cross-user SHARING. This
-- PAYMENTS-SIDE migration installs the SERVER-SIDE entitlement TRUTH that the sharing
-- gate consumes. Premium/trial entitlement was previously enforced ONLY client-side: the
-- signup trigger writes status='trial', plan=Premium, trial_end=NOW()+30d, and the ONLY
-- thing that downgraded an expired trial was the CLIENT calling downgrade_to_free(). A
-- tampered client (or direct PostgREST calls) could keep status='trial' with a long-past
-- trial_end forever -> permanent free Premium.
--
-- This migration adds the SERVER-SIDE truth and the trial-expiry job:
--   1. is_premium_active(uid): the canonical entitlement predicate, computed from
--      subscriptions + subscription_plans, NEVER from `status` alone:
--        premium == (status='active' AND plan=Premium)
--                OR (status='trial'  AND trial_end > NOW())   -- expired trial => NOT premium
--   2. expire_overdue_trials(): a sweep that flips expired trials to Free/active,
--      scheduled hourly via pg_cron when the extension is present.
--
-- The SHARING gate that USES is_premium_active() (the data_shares owner-INSERT WITH CHECK)
-- is added by the money_tracker migration database/setup/apply-premium-sharing-gate.sql
-- (and is folded into both complete-setup.sql installers). Order does not matter: this
-- file (re)defines is_premium_active with its full body; the messaging schema ships a
-- fail-closed bootstrap definition so it exists regardless of load order. (Messaging is
-- NO LONGER gated — the former apply-premium-message-gate.sql files were retired.)
--
-- ADDITIVE ONLY: never drops a table, never rewrites/deletes rows. Safe to re-run.
-- Mirrors payments_app/backend/sql/complete-setup.sql and the money_tracker installer.
-- ============================================================================

BEGIN;

-- ---------------------------------------------------------------------------
-- is_premium_active(uid) — the single source of truth for current entitlement.
-- SECURITY DEFINER + pinned search_path so the messages-INSERT RLS gate (secure_db)
-- can evaluate it for any caller regardless of the subscriptions row's own RLS. It
-- reads only the passed uid's single row and returns a boolean (no other user's data).
-- The RLS gate always passes auth.uid(), so the answer is scoped to the acting user.
-- ---------------------------------------------------------------------------
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

GRANT EXECUTE ON FUNCTION is_premium_active(UUID) TO authenticated;

-- ---------------------------------------------------------------------------
-- expire_overdue_trials() — server-side trial-expiry sweep (replaces the client-only
-- downgrade path). is_premium_active() already denies expired trials, so enforcement
-- is correct even before this sweep runs; the sweep keeps stored rows honest.
-- ---------------------------------------------------------------------------
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

-- Sweep runs as the service role via pg_cron — never grant it to `authenticated`
-- (a client must never be able to mass-mutate other users' subscription rows).
REVOKE ALL ON FUNCTION expire_overdue_trials() FROM PUBLIC;

COMMIT;

-- ---------------------------------------------------------------------------
-- Schedule the hourly sweep via pg_cron IF the extension is available. On Supabase,
-- enable pg_cron once (Dashboard > Database > Extensions > pg_cron) then re-run this
-- file (or run the cron.schedule call below manually). If pg_cron is absent this is a
-- safe no-op — is_premium_active() already denies expired trials, so revenue is
-- protected even without the cron. Kept OUTSIDE the transaction above because some
-- pg_cron versions disallow cron.schedule inside an explicit transaction block.
-- ---------------------------------------------------------------------------
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        BEGIN
            PERFORM cron.schedule(
                'expire-overdue-trials',
                '0 * * * *',               -- top of every hour
                $cron$SELECT public.expire_overdue_trials();$cron$
            );
            RAISE NOTICE 'pg_cron: scheduled job "expire-overdue-trials" (hourly).';
        EXCEPTION WHEN OTHERS THEN
            RAISE NOTICE 'pg_cron present but scheduling failed (likely already scheduled): %', SQLERRM;
        END;
    ELSE
        RAISE NOTICE 'pg_cron not installed: trial-expiry sweep NOT scheduled. is_premium_active() still denies expired trials. Enable pg_cron then re-run this file.';
    END IF;
END $$;
