-- ============================================================================
-- ADD stripe_webhook_events  (non-destructive, idempotent migration)
-- ============================================================================
-- Run this on a LIVE database that already has the subscription system but is
-- MISSING the stripe_webhook_events table. Without this table the stripe-webhook
-- has no way to de-duplicate redelivered Stripe events: Stripe retries deliver
-- the SAME event id, so non-idempotent handlers can double-process a payment.
--
-- The stripe-webhook records every received event id here BEFORE processing it,
-- via an atomic INSERT ... ON CONFLICT (stripe_event_id) DO NOTHING using the
-- service role. The insert itself is the lock: if a row already existed the
-- webhook short-circuits with 200 and skips reprocessing. After successful
-- handling the webhook sets processed = true.
--
-- This script ONLY adds stripe_webhook_events. It does NOT drop or alter any
-- existing table and is safe to run more than once (CREATE TABLE IF NOT EXISTS).
--
-- Intentionally MINIMAL: only the event id, type, a processed flag and a
-- timestamp. The full event payload is NOT stored (avoids persisting PII).
-- Service-role only: RLS is enabled and NO grants are issued to `authenticated`
-- (the webhook runs as the service role, which bypasses RLS).
-- ============================================================================

CREATE TABLE IF NOT EXISTS stripe_webhook_events (
    stripe_event_id TEXT PRIMARY KEY,
    type TEXT,
    processed BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE stripe_webhook_events ENABLE ROW LEVEL SECURITY;
-- No policies and no grants to `authenticated`: only the service role (which
-- bypasses RLS) may read/write this table.
