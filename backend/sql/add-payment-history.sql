-- ============================================================================
-- ADD payment_history  (non-destructive, idempotent migration)
-- ============================================================================
-- Run this on a LIVE database that already has the subscription system but is
-- MISSING the payment_history table. Without this table every payment write
-- from the stripe-webhook 404s (PostgREST: relation does not exist) and is
-- silently swallowed, so no payment is ever recorded.
--
-- This script ONLY adds payment_history. It does NOT drop or alter any existing
-- table and is safe to run more than once (CREATE TABLE IF NOT EXISTS,
-- CREATE INDEX IF NOT EXISTS, DROP POLICY IF EXISTS before CREATE POLICY).
--
-- The stripe-webhook writes here with the service role (recordPayment() in
-- edge-functions/stripe-webhook.ts) and re-reads by (user_id, stripe_invoice_id)
-- to attach the payment id to its notifications; the subscription UI reads it
-- back (PaymentService.getPaymentHistory + renderPaymentHistory).
--
-- NOTE: amount is stored in MAJOR units (dollars/euros). The webhook divides
-- Stripe's integer cents by 100 before writing (e.g. invoice.amount_paid / 100).
-- The legacy `payments` table is NOT used by the webhook because it lacks
-- stripe_invoice_id (needed for the read-backs) and stores amount_cents.
-- ============================================================================

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
DROP POLICY IF EXISTS payment_history_select_own ON payment_history;
CREATE POLICY payment_history_select_own ON payment_history
    FOR SELECT USING (auth.uid() = user_id);

-- Writes are performed by the stripe-webhook with the service role (which
-- bypasses RLS), so authenticated users get SELECT only — never INSERT/UPDATE.
GRANT SELECT ON payment_history TO authenticated;
GRANT USAGE, SELECT ON SEQUENCE payment_history_id_seq TO authenticated;
