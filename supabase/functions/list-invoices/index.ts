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

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
}
const json = (body: unknown, status: number) =>
  new Response(JSON.stringify(body), { status, headers: { ...cors, "Content-Type": "application/json" } })

serve(async (req) => {
  if (req.method === "OPTIONS") return new Response(null, { status: 204, headers: cors })
  if (req.method !== "POST") return json({ error: "Method not allowed" }, 405)
  if (!supabaseUrl || !serviceRoleKey) return json({ error: "Server configuration error" }, 500)

  try {
    // Identity from the verified token only.
    const authHeader = req.headers.get("Authorization") ?? ""
    const jwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : ""
    if (!jwt) return json({ error: "Missing authorization header" }, 401)

    const supabase = createClient(supabaseUrl, serviceRoleKey, { auth: { persistSession: false } })
    const { data: { user }, error: authError } = await supabase.auth.getUser(jwt)
    if (authError || !user) return json({ error: "Invalid or expired token" }, 401)

    // Look up the user's Stripe customer id from THEIR subscription row (never from body).
    const { data: sub } = await supabase
      .from("subscriptions")
      .select("stripe_customer_id")
      .eq("user_id", user.id)
      .single()

    const customerId = sub?.stripe_customer_id
    if (!customerId) return json({ invoices: [] }, 200) // no Stripe customer yet (free/trial)

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
    return json({ invoices: result }, 200)
  } catch (error) {
    console.error("[list-invoices] error:", (error as Error).message)
    return json({ error: "Failed to load invoices" }, 500)
  }
})
