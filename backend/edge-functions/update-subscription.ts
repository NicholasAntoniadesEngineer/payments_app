/**
 * Supabase Edge Function: update-subscription
 *
 * Handles subscription downgrades/cancellations and date syncs.
 *
 * SECURITY: identity comes ONLY from the verified JWT. The Stripe subscription/
 * customer acted on is read from the caller's OWN `subscriptions` row server-side;
 * body ids are accepted only if they match the user's row (never trusted blindly).
 *
 * Modes (by body):
 *   { syncDates: true }                          -> pull current_period_*/status from Stripe into the DB
 *   { changeType: 'downgrade', recurringBillingEnabled: false } -> cancel at period end (drop to Free later)
 *   { changeType: 'downgrade', newPlanId, recurringBillingEnabled: true } -> schedule a plan change at period end
 *
 * DEPLOYMENT: create `update-subscription`; secrets STRIPE_SECRET_KEY (SUPABASE_* auto-injected).
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.7"

const stripeKey = Deno.env.get("STRIPE_RESTRICTED_KEY") || Deno.env.get("STRIPE_SECRET_KEY")
if (!stripeKey) throw new Error("STRIPE_SECRET_KEY is required")
const stripe = new Stripe(stripeKey, { apiVersion: "2023-10-16" })

const supabaseUrl = Deno.env.get("SUPABASE_URL")
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
}
const json = (b: unknown, s: number) =>
  new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } })

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors })
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405)
  if (!supabaseUrl || !serviceRoleKey) return json({ error: "Server configuration error" }, 500)

  try {
    const authHeader = req.headers.get("Authorization") ?? ""
    const jwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : ""
    if (!jwt) return json({ error: "Missing authorization header" }, 401)

    const supabase = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } })
    const { data: { user }, error: authError } = await supabase.auth.getUser(jwt)
    if (authError || !user) return json({ error: "Invalid or expired token" }, 401)

    const body = await req.json().catch(() => ({}))

    // The subscription we act on is ALWAYS the caller's own row.
    const { data: sub, error: subErr } = await supabase
      .from("subscriptions")
      .select("id, stripe_subscription_id, stripe_customer_id, current_period_end, plan_id")
      .eq("user_id", user.id)
      .single()
    if (subErr || !sub) return json({ error: "Subscription not found" }, 404)

    const stripeSubId = sub.stripe_subscription_id
    if (!stripeSubId) {
      // No active Stripe subscription (free/trial) — nothing to change at Stripe.
      return json({ success: true, note: "no_stripe_subscription" }, 200)
    }

    // --- syncDates: pull authoritative dates/status from Stripe ---
    if (body.syncDates === true) {
      const s = await stripe.subscriptions.retrieve(stripeSubId)
      await supabase.from("subscriptions").update({
        status: s.status === "active" ? "active" : (s.status === "trialing" ? "trial" : s.status),
        current_period_start: new Date(s.current_period_start * 1000).toISOString(),
        current_period_end: new Date(s.current_period_end * 1000).toISOString(),
        cancel_at_period_end: s.cancel_at_period_end,
      }).eq("user_id", user.id)
      return json({ success: true, synced: true }, 200)
    }

    // --- downgrade / cancel-at-period-end ---
    if (body.changeType === "downgrade") {
      // Stop renewal; the user keeps Premium until current_period_end, then drops.
      const s = await stripe.subscriptions.update(stripeSubId, { cancel_at_period_end: true })

      const update: Record<string, unknown> = {
        cancel_at_period_end: true,
        current_period_end: new Date(s.current_period_end * 1000).toISOString(),
      }
      // Record the pending target plan (the stripe-webhook applies it at period end).
      if (body.newPlanId) {
        update.pending_plan_id = body.newPlanId
        update.pending_change_at = new Date(s.current_period_end * 1000).toISOString()
      }
      await supabase.from("subscriptions").update(update).eq("user_id", user.id)
      return json({ success: true, cancel_at_period_end: true, effective_at: update.current_period_end }, 200)
    }

    return json({ error: "Unsupported changeType" }, 400)
  } catch (error) {
    console.error("[update-subscription] error:", (error as Error).message)
    return json({ error: "Failed to update subscription" }, 500)
  }
})
