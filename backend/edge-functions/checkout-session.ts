/**
 * Supabase Edge Function: checkout-session
 *
 * Creates a Stripe Checkout session for Premium subscription.
 * Automatically creates Stripe customer if needed.
 *
 * DEPLOYMENT:
 * 1. Supabase Dashboard → Edge Functions → Create function
 * 2. Name: checkout-session
 * 3. Set env: STRIPE_SECRET_KEY
 * 4. Deploy this code
 *
 * USAGE:
 * POST https://xxx.supabase.co/functions/v1/checkout-session
 * Headers: { "Authorization": "Bearer <user-token>" }
 * Body: {
 *   "successUrl": "https://app.com/success",
 *   "cancelUrl": "https://app.com/pricing"
 * }
 *
 * Returns: { "url": "https://checkout.stripe.com/..." }
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno"
import { createClient } from "https://esm.sh/@supabase/supabase-js@2.39.7"

const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY") || "", {
  apiVersion: "2023-10-16",
})

const supabaseUrl = Deno.env.get("SUPABASE_URL")!
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!

// Both front-ends currently share this GitHub Pages origin; localhost for dev.
const ALLOWED_RETURN_ORIGINS = [
  "https://nicholasantoniadesengineer.github.io",
  "http://localhost",
  "http://127.0.0.1",
]

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
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
  }
}
const json = (body: unknown, status: number, cors: Record<string, string>) =>
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
  const cors = corsHeaders(req)

  // CORS
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: cors })
  }

  if (req.method !== "POST") {
    return json({ error: "Method not allowed" }, 405, cors)
  }

  // Identity from the verified token ONLY. Reject missing/invalid auth as 401
  // and bad input as 400 BEFORE entering the try (generic 500 in catch only).
  const authHeader = req.headers.get("Authorization") ?? ""
  const jwt = authHeader.startsWith("Bearer ") ? authHeader.slice(7).trim() : ""
  if (!jwt) return json({ error: "Missing authorization header" }, 401, cors)

  const supabase = createClient(supabaseUrl, supabaseServiceKey, { auth: { persistSession: false } })
  const { data: { user }, error: authError } = await supabase.auth.getUser(jwt)
  if (authError || !user) return json({ error: "Invalid or expired token" }, 401, cors)

  const { successUrl, cancelUrl } = await req.json().catch(() => ({}))
  if (!successUrl || typeof successUrl !== "string" || !isAllowedReturnUrl(successUrl)) {
    return json({ error: "Invalid successUrl" }, 400, cors)
  }
  if (!cancelUrl || typeof cancelUrl !== "string" || !isAllowedReturnUrl(cancelUrl)) {
    return json({ error: "Invalid cancelUrl" }, 400, cors)
  }

  try {
    // Get user's subscription.
    // NOTE: do NOT embed subscription_plans here — subscriptions has TWO FKs to
    // subscription_plans (plan_id and pending_plan_id), so the auto-embed is ambiguous
    // ("more than one relationship was found"). The plan is fetched separately below.
    const { data: subscription, error: subError } = await supabase
      .from("subscriptions")
      .select("*")
      .eq("user_id", user.id)
      .single()

    if (subError) {
      throw new Error(`Failed to fetch subscription: ${subError.message}`)
    }

    // Get Premium plan
    const { data: premiumPlan, error: planError } = await supabase
      .from("subscription_plans")
      .select("*")
      .eq("name", "Premium")
      .single()

    if (planError || !premiumPlan) {
      throw new Error("Premium plan not found")
    }

    if (!premiumPlan.stripe_price_id) {
      throw new Error("Premium plan missing Stripe price ID")
    }

    // Create or get Stripe customer
    let customerId = subscription.stripe_customer_id

    if (!customerId) {
      console.log("[checkout-session] Creating new Stripe customer...")
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: {
          supabase_user_id: user.id,
        },
      })
      customerId = customer.id

      // Save customer ID to database
      await supabase
        .from("subscriptions")
        .update({ stripe_customer_id: customerId })
        .eq("user_id", user.id)

      console.log("[checkout-session] ✓ Customer created:", customerId)
    }

    // Create checkout session
    const session = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [
        {
          price: premiumPlan.stripe_price_id,
          quantity: 1,
        },
      ],
      success_url: successUrl,
      cancel_url: cancelUrl,
      metadata: {
        supabase_user_id: user.id,
        plan_id: premiumPlan.id.toString(),
      },
      // Propagate identity onto the Stripe SUBSCRIPTION object too, so subscription
      // lifecycle events (updated/deleted/invoice) can resolve the user even if the
      // customer metadata is ever missing. Keys match the webhook's snake_case reads.
      subscription_data: {
        metadata: {
          supabase_user_id: user.id,
          plan_id: premiumPlan.id.toString(),
        },
      },
    })

    console.log("[checkout-session] ✓ Checkout session created:", session.id)

    return json({ url: session.url, session_id: session.id }, 200, cors)

  } catch (error) {
    console.error("[checkout-session] error:", (error as Error).message)
    return json({ error: "Failed to create checkout session" }, 500, cors)
  }
})
