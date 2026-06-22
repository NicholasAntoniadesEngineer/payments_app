/**
 * Supabase Edge Function: create-portal-session
 *
 * Creates a Stripe Customer Portal session (manage payment method, invoices, billing).
 *
 * SECURITY: identity comes ONLY from the verified JWT. The Stripe customer is looked
 * up from the caller's OWN `subscriptions` row server-side — the request body is NEVER
 * trusted for the customer id (previously an unauthenticated IDOR). `returnUrl` is
 * validated against an origin allowlist.
 *
 * DEPLOYMENT: create `create-portal-session`; secret STRIPE_SECRET_KEY (or
 * STRIPE_RESTRICTED_KEY). SUPABASE_URL + SUPABASE_SERVICE_ROLE_KEY are auto-injected.
 *
 * USAGE: POST /functions/v1/create-portal-session
 *   Headers: { Authorization: Bearer <jwt> }
 *   Body: { returnUrl: "https://...allowed-origin..." }
 *   Returns: { url }
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.7"

const stripeKey = Deno.env.get("STRIPE_RESTRICTED_KEY") || Deno.env.get("STRIPE_SECRET_KEY")
if (!stripeKey) {
  throw new Error("STRIPE_RESTRICTED_KEY or STRIPE_SECRET_KEY is required")
}
const stripe = new Stripe(stripeKey, { apiVersion: "2023-10-16" })

const supabaseUrl = Deno.env.get("SUPABASE_URL")
const serviceRoleKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")

// Both front-ends currently share this GitHub Pages origin; localhost for dev.
const ALLOWED_RETURN_ORIGINS = [
  "https://nicholasantoniadesengineer.github.io",
  "http://localhost",
  "http://127.0.0.1",
]

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
}
const json = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } })

function isAllowedReturnUrl(url: string): boolean {
  try {
    const u = new URL(url)
    return ALLOWED_RETURN_ORIGINS.some((o) => {
      const ao = new URL(o)
      return u.protocol === ao.protocol && u.hostname === ao.hostname
    })
  } catch {
    return false
  }
}

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors })
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405)
  if (!supabaseUrl || !serviceRoleKey) return json({ error: "Server configuration error" }, 500)

  try {
    // Identity from the verified token ONLY.
    const authHeader = req.headers.get("Authorization") ?? ""
    const jwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : ""
    if (!jwt) return json({ error: "Missing authorization header" }, 401)

    const supabase = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } })
    const { data: { user }, error: authError } = await supabase.auth.getUser(jwt)
    if (authError || !user) return json({ error: "Invalid or expired token" }, 401)

    const { returnUrl } = await req.json().catch(() => ({}))
    if (!returnUrl || typeof returnUrl !== "string" || !isAllowedReturnUrl(returnUrl)) {
      return json({ error: "Invalid returnUrl" }, 400)
    }

    // The Stripe customer is ALWAYS the caller's own — never from the body.
    const { data: sub } = await supabase
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .single()

    const customerId = sub?.stripe_customer_id
    if (!customerId) return json({ error: "No billing account found" }, 404)

    const session = await stripe.billingPortal.sessions.create({
      customer: customerId,
      return_url: returnUrl,
    })
    return json({ url: session.url }, 200)
  } catch (error) {
    console.error("[create-portal-session] error:", (error as Error).message)
    return json({ error: "Failed to create portal session" }, 500)
  }
})
