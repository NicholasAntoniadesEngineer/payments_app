/**
 * Supabase Edge Function: list-invoices
 *
 * Returns the authenticated user's Stripe invoices for the "Recent Invoices" panel.
 *
 * SECURITY: identity is derived ONLY from the verified JWT, and the Stripe customer
 * id is looked up from the user's own `subscriptions` row server-side — the request
 * body is never trusted for identity or customer id.
 *
 * DEPLOYMENT:
 *   Supabase Dashboard -> Edge Functions -> create `list-invoices`
 *   Secrets: STRIPE_SECRET_KEY (or STRIPE_RESTRICTED_KEY). SUPABASE_URL +
 *   SUPABASE_SERVICE_ROLE_KEY are injected automatically.
 *
 * USAGE: POST /functions/v1/list-invoices  Headers: { Authorization: Bearer <jwt> }
 * Returns: { invoices: [{ id, number, amount_paid, currency, status, created, hosted_invoice_url, invoice_pdf }] }
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

// CORS allowlist (EB-10): reflect the request Origin back in ACAO only if it is
// in the allowlist, otherwise fall back to the GitHub Pages origin. Never echo
// an arbitrary Origin with `*`.
const GITHUB_PAGES_ORIGIN = "https://nicholasantoniadesengineer.github.io"
const ALLOWED_ORIGINS = new Set([
  GITHUB_PAGES_ORIGIN,
  "http://localhost",
  "http://127.0.0.1",
])
function corsHeaders(req: Request): Record<string, string> {
  const origin = req.headers.get("Origin") ?? ""
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS.has(origin) ? origin : GITHUB_PAGES_ORIGIN,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  }
}
const json = (body: unknown, status: number, cors: Record<string, string>) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } })

serve(async (req) => {
  const cors = corsHeaders(req)

  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors })
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405, cors)
  if (!supabaseUrl || !serviceRoleKey) return json({ error: "Server configuration error" }, 500, cors)

  try {
    // Identity from the verified token only.
    const authHeader = req.headers.get("Authorization") ?? ""
    const jwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : ""
    if (!jwt) return json({ error: "Missing authorization header" }, 401, cors)

    const supabase = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } })
    const { data: { user }, error: authError } = await supabase.auth.getUser(jwt)
    if (authError || !user) return json({ error: "Invalid or expired token" }, 401, cors)

    // Look up the user's Stripe customer id from THEIR subscription row (never from body).
    const { data: sub } = await supabase
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .single()

    const customerId = sub?.stripe_customer_id
    if (!customerId) return json({ invoices: [] }, 200, cors) // no Stripe customer yet (free/trial)

    const invoices = await stripe.invoices.list({ customer: customerId, limit: 12 })
    const result = invoices.data.map((inv) => ({
      id: inv.id,
      number: inv.number,
      amount_paid: inv.amount_paid,
      currency: inv.currency,
      status: inv.status,
      created: inv.created,
      hosted_invoice_url: inv.hosted_invoice_url,
      invoice_pdf: inv.invoice_pdf,
    }))
    return json({ invoices: result }, 200, cors)
  } catch (error) {
    console.error("[list-invoices] error:", (error as Error).message)
    return json({ error: "Failed to load invoices" }, 500, cors)
  }
})
