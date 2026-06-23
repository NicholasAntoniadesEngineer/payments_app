/**
 * Supabase Edge Function: stripe-webhook
 * 
 * Handles Stripe webhook events to:
 * - Update subscription status in database
 * - Record payment history
 * - Generate and store invoices
 * - Send confirmation emails
 * 
 * DEPLOYMENT INSTRUCTIONS:
 * 1. In Supabase Dashboard, go to Edge Functions
 * 2. Click "Create a new function"
 * 3. Name it: stripe-webhook
 * 4. Copy the code from this file into the function
 * 5. Set environment variables:
 *    - STRIPE_RESTRICTED_KEY = your_stripe_restricted_key_here
 *    - STRIPE_WEBHOOK_SECRET = your_webhook_signing_secret_here (starts with whsec_)
 *    Note: SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY are available by default in Edge Functions
 * 6. Deploy the function
 * 
 * STRIPE WEBHOOK SETUP:
 * 1. Go to Stripe Dashboard → Developers → Webhooks
 * 2. Click "Add endpoint"
 * 3. Endpoint URL: https://ofutzrxfbrgtbkyafndv.supabase.co/functions/v1/stripe-webhook
 * 4. Select events to listen to:
 *    - checkout.session.completed
 *    - customer.subscription.created
 *    - customer.subscription.updated
 *    - customer.subscription.deleted
 *    - invoice.payment_succeeded
 *    - invoice.payment_failed
 *    - payment_intent.succeeded
 * 5. Copy the webhook signing secret (whsec_xxxxx) to environment variable
 * 
 * USAGE:
 * Stripe automatically sends webhook events to this endpoint
 */

import { serve } from "https://deno.land/std@0.168.0/http/server.ts"
import Stripe from "https://esm.sh/stripe@14.21.0?target=deno"

const stripeKey = Deno.env.get("STRIPE_RESTRICTED_KEY") || Deno.env.get("STRIPE_SECRET_KEY")
const webhookSecret = Deno.env.get("STRIPE_WEBHOOK_SECRET")
// Use default Supabase secrets available in Edge Functions
const supabaseUrl = Deno.env.get("SUPABASE_URL")
const supabaseServiceKey = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")

if (!stripeKey) {
  throw new Error("STRIPE_RESTRICTED_KEY or STRIPE_SECRET_KEY environment variable is required")
}

if (!webhookSecret) {
  throw new Error("STRIPE_WEBHOOK_SECRET environment variable is required")
}

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error("SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY should be available by default in Edge Functions")
}

const stripe = new Stripe(stripeKey, {
  apiVersion: "2023-10-16",
})

// Initialize Supabase client for direct database access
const supabaseClient = {
  url: supabaseUrl,
  key: supabaseServiceKey,
}

// Format a money amount using the ACTUAL currency, not a hardcoded "$".
// Falls back to the uppercased currency code for anything outside the symbol map.
const CURRENCY_SYMBOLS: Record<string, string> = {
  usd: "$",
  gbp: "£",
  eur: "€",
}
function formatAmount(amount: number, currency: string): string {
  const code = (currency || "").toLowerCase()
  const symbol = CURRENCY_SYMBOLS[code]
  const value = amount.toFixed(2)
  return symbol ? `${symbol}${value}` : `${value} ${code.toUpperCase()}`
}

serve(async (req) => {
  console.log("[stripe-webhook] ========== WEBHOOK REQUEST RECEIVED ==========")
  const startTime = Date.now()

  // Handle CORS preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Stripe-Signature",
      },
    })
  }

  if (req.method !== "POST") {
    return new Response(
      JSON.stringify({ error: "Method not allowed. Use POST." }),
      { 
        status: 405,
        headers: { 
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        } 
      }
    )
  }

  try {
    // Get the raw body for signature verification
    const body = await req.text()
    const signature = req.headers.get("stripe-signature")

    if (!signature) {
      console.error("[stripe-webhook] ❌ No Stripe signature found")
      return new Response(
        JSON.stringify({ error: "No signature" }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      )
    }

    // Verify webhook signature
    console.log("[stripe-webhook] Step 1: Verifying webhook signature...")
    let event
    try {
      event = stripe.webhooks.constructEvent(body, signature, webhookSecret)
      console.log("[stripe-webhook] ✅ Webhook signature verified")
    } catch (err) {
      console.error("[stripe-webhook] ❌ Webhook signature verification failed:", err.message)
      return new Response(
        JSON.stringify({ error: `Webhook Error: ${err.message}` }),
        { status: 400, headers: { "Content-Type": "application/json" } }
      )
    }

    // Log webhook event
    console.log("[stripe-webhook] Step 2: Processing event:", {
      type: event.type,
      id: event.id,
      created: new Date(event.created * 1000).toISOString()
    })

    // Idempotency / event de-duplication (PAY-2/EB-02) — COMPLETION-based (M-3).
    //
    // The bug this fixes: the old code claimed the event on RECEIPT (INSERT ...
    // ON CONFLICT DO NOTHING) and short-circuited 200 on ANY pre-existing row.
    // A handler that then failed (it returned {success:false} as HTTP 200) or a
    // crash after the claim INSERT committed left `processed=false` forever — and
    // every Stripe redelivery saw the row and 200'd without ever running the
    // handler. A dropped cancellation/payment-failure → user kept Premium.
    //
    // The fix: idempotency keys on COMPLETION, not receipt.
    //   firstDelivery  -> our INSERT won the race: run the handler now.
    //   alreadyProcessed (processed=true) -> short-circuit 200, do NOT re-run.
    //   inFlight (row exists, processed=false) -> a prior delivery claimed it but
    //       never finished (failure/crash). RE-RUN the (idempotent, PATCH-by-user)
    //       handler. processed flips to true only on success below; on failure we
    //       return 500 so Stripe keeps retrying.
    const claim = await claimWebhookEvent(event)
    if (claim === "alreadyProcessed") {
      console.log("[stripe-webhook] ⏭️ Already processed — skipping:", event.id)
      return new Response(
        JSON.stringify({ received: true, duplicate: true, status: "alreadyProcessed" }),
        {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          }
        }
      )
    }
    if (claim === "inFlight") {
      // Prior delivery claimed but did not complete — reprocess idempotently.
      console.log("[stripe-webhook] 🔁 Prior delivery did not complete — reprocessing:", event.id)
    }

    // Handle different event types
    let result
    switch (event.type) {
      case "checkout.session.completed":
        result = await handleCheckoutSessionCompleted(event.data.object)
        break
      
      case "customer.subscription.created":
      case "customer.subscription.updated":
        result = await handleSubscriptionUpdated(event.data.object)
        break
      
      case "customer.subscription.deleted":
        result = await handleSubscriptionDeleted(event.data.object)
        break
      
      case "invoice.payment_succeeded":
        result = await handleInvoicePaymentSucceeded(event.data.object)
        break
      
      case "invoice.payment_failed":
        result = await handleInvoicePaymentFailed(event.data.object)
        break
      
      case "payment_intent.succeeded":
        result = await handlePaymentIntentSucceeded(event.data.object)
        break
      
      default:
        console.log("[stripe-webhook] ⚠️ Unhandled event type:", event.type)
        result = { success: true, message: `Unhandled event type: ${event.type}` }
    }

    // M-3: completion-based idempotency. If the handler did NOT succeed, do NOT
    // mark the event processed and return 500 so Stripe RETRIES (the claim row
    // stays processed=false → the retry takes the inFlight/reprocess path above).
    // Previously a handler failure was swallowed into HTTP 200, so Stripe never
    // retried and the entitlement/cancellation write was lost permanently.
    if (!result || result.success !== true) {
      console.error("[stripe-webhook] ❌ Handler did not succeed — returning 500 for Stripe retry:", {
        type: event.type, id: event.id, result
      })
      return new Response(
        JSON.stringify({ received: false, error: "handler_failed", result }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            "Access-Control-Allow-Origin": "*",
          }
        }
      )
    }

    // Success: NOW flip processed=true so future redeliveries short-circuit.
    await markWebhookEventProcessed(event.id)

    const totalElapsed = Date.now() - startTime
    console.log("[stripe-webhook] ========== WEBHOOK PROCESSED ==========")
    console.log("[stripe-webhook] Result:", result)
    console.log("[stripe-webhook] Total time:", `${totalElapsed}ms`)

    return new Response(
      JSON.stringify({ received: true, result }),
      {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        }
      }
    )
  } catch (error) {
    console.error("[stripe-webhook] ========== WEBHOOK ERROR ==========")
    console.error("[stripe-webhook] Error details:", {
      message: error.message,
      stack: error.stack,
      name: error.name
    })

    return new Response(
      JSON.stringify({ error: "Webhook processing failed" }),
      {
        status: 500,
        headers: {
          "Content-Type": "application/json",
          "Access-Control-Allow-Origin": "*",
        }
      }
    )
  }
})

type ClaimResult = "firstDelivery" | "alreadyProcessed" | "inFlight"

/**
 * Claim a webhook event for processing — COMPLETION-based idempotency (M-3).
 *
 * Step 1: atomic INSERT ... ON CONFLICT (stripe_event_id) DO NOTHING with
 *         return=representation. The INSERT is the lock — NO SELECT-then-INSERT,
 *         so there is no TOCTOU window on first delivery.
 *           - a row came back  -> WE inserted it -> "firstDelivery".
 *           - empty array / 409 -> the id already existed (a redelivery).
 *
 * Step 2 (only on conflict): SELECT the existing row's `processed` flag to decide
 *         what kind of redelivery this is:
 *           - processed = true  -> "alreadyProcessed": the handler completed on a
 *                                  prior delivery; caller short-circuits 200.
 *           - processed = false -> "inFlight": a prior delivery claimed the event
 *                                  but never finished (handler failure / crash);
 *                                  caller RE-RUNS the idempotent handler.
 *
 * This replaces the old receipt-based logic that returned a bare boolean and made
 * ANY pre-existing row short-circuit 200 — which permanently dropped events whose
 * first delivery claimed the row but failed before flipping `processed`.
 *
 * Minimal columns only (no payload/PII). On a genuine DB error we throw so the
 * outer try/catch returns 500 and Stripe retries — we never blanket-convert a
 * 500 into a 200.
 */
async function claimWebhookEvent(event: any): Promise<ClaimResult> {
  console.log("[stripe-webhook] Claiming webhook event (completion-based idempotency)...")

  const response = await fetch(`${supabaseClient.url}/rest/v1/stripe_webhook_events`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "apikey": supabaseClient.key,
      "Authorization": `Bearer ${supabaseClient.key}`,
      // ignore-duplicates: ON CONFLICT DO NOTHING; representation: return rows so
      // we can detect whether a row was actually inserted.
      "Prefer": "resolution=ignore-duplicates,return=representation"
    },
    body: JSON.stringify({
      stripe_event_id: event.id,
      type: event.type,
      processed: false
    })
  })

  // 409 (some PostgREST configs) also means "already present" — fall through to
  // the processed-flag lookup rather than treating it as success or error.
  if (response.status !== 409) {
    if (!response.ok) {
      const errorText = await response.text()
      // Genuine failure (e.g. table missing) — do NOT swallow. Throw so the outer
      // handler returns 500 and Stripe retries.
      throw new Error(`Failed to claim webhook event: ${response.status} ${errorText}`)
    }
    const rows = await response.json().catch(() => [])
    if (Array.isArray(rows) && rows.length > 0) {
      console.log("[stripe-webhook] ✅ Event claimed (first delivery)")
      return "firstDelivery"
    }
  } else {
    console.log("[stripe-webhook] Event already present (409) — checking processed flag")
  }

  // Conflict: the event id already exists. Read its processed flag to decide
  // whether the prior delivery actually completed.
  return await readClaimState(event.id)
}

/**
 * Read the completion state of an already-claimed event (M-3 helper).
 * Returns "alreadyProcessed" if processed=true, else "inFlight". A missing row
 * (lost the insert race AND the row vanished) is treated as inFlight so we err
 * toward reprocessing the idempotent handler rather than dropping the event.
 */
async function readClaimState(eventId: string): Promise<ClaimResult> {
  const response = await fetch(
    `${supabaseClient.url}/rest/v1/stripe_webhook_events?stripe_event_id=eq.${eventId}&select=processed`,
    {
      method: "GET",
      headers: {
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
      }
    }
  )

  if (!response.ok) {
    const errorText = await response.text()
    // Cannot determine state — throw so the outer handler returns 500 and Stripe
    // retries (never silently drop).
    throw new Error(`Failed to read webhook event state: ${response.status} ${errorText}`)
  }

  const rows = await response.json().catch(() => [])
  const processed = Array.isArray(rows) && rows.length > 0 ? rows[0].processed === true : false
  console.log(processed
    ? "[stripe-webhook] Event already processed — will short-circuit"
    : "[stripe-webhook] Event claimed but not processed (inFlight) — will reprocess")
  return processed ? "alreadyProcessed" : "inFlight"
}

/**
 * Mark a previously-claimed webhook event as fully processed.
 * Best-effort: failure here does not break idempotency (the unique id row
 * already prevents reprocessing) and must not fail the webhook.
 */
async function markWebhookEventProcessed(eventId: string) {
  try {
    const response = await fetch(
      `${supabaseClient.url}/rest/v1/stripe_webhook_events?stripe_event_id=eq.${eventId}`,
      {
        method: "PATCH",
        headers: {
          "Content-Type": "application/json",
          "apikey": supabaseClient.key,
          "Authorization": `Bearer ${supabaseClient.key}`,
          "Prefer": "return=minimal"
        },
        body: JSON.stringify({ processed: true })
      }
    )
    if (!response.ok) {
      const errorText = await response.text()
      console.warn("[stripe-webhook] ⚠️ Failed to mark event processed:", errorText)
    }
  } catch (error) {
    console.warn("[stripe-webhook] ⚠️ Error marking event processed:", error)
  }
}

/**
 * Handle checkout.session.completed event
 * Updates subscription when checkout is completed
 */
async function handleCheckoutSessionCompleted(session: any) {
  console.log("[stripe-webhook] Handling checkout.session.completed...")
  
  try {
    const userId = session.metadata?.supabase_user_id
    const customerId = session.customer
    const subscriptionId = session.subscription
    const planId = session.metadata?.plan_id

    if (!userId) {
      console.warn("[stripe-webhook] ⚠️ No userId in session metadata")
      return { success: false, error: "No userId in metadata" }
    }

    console.log("[stripe-webhook] Checkout session data:", {
      userId,
      customerId,
      subscriptionId,
      planId
    })

    // Ensure no other active subscriptions exist for this customer
    // This prevents multiple subscriptions from being active simultaneously
    console.log("[stripe-webhook] Checking for existing active subscriptions...")
    const existingSubs = await stripe.subscriptions.list({
      customer: customerId,
      status: 'active',
      limit: 10
    })
    
    // Cancel all existing subscriptions except the new one
    for (const sub of existingSubs.data) {
      if (sub.id !== subscriptionId) {
        try {
          console.log(`[stripe-webhook] Cancelling duplicate subscription: ${sub.id}`)
          await stripe.subscriptions.cancel(sub.id)  // immediate, terminal cancellation
          console.log(`[stripe-webhook] ✅ Cancelled subscription: ${sub.id}`)
        } catch (cancelError) {
          console.error(`[stripe-webhook] ⚠️ Error cancelling subscription ${sub.id}:`, cancelError.message)
          // Continue - try to cancel others even if one fails
        }
      }
    }

    // Get subscription details from Stripe
    let subscription: any = null
    if (subscriptionId) {
      subscription = await stripe.subscriptions.retrieve(subscriptionId)
    }

    // Get customer details
    let customer: any = null
    if (customerId) {
      customer = await stripe.customers.retrieve(customerId)
    }

    // Update subscription in database (NEW OPTIMAL SCHEMA)
    const updateData: any = {
      status: "active",  // Status is source of truth from Stripe
      stripe_customer_id: customerId,
      stripe_subscription_id: subscriptionId,
      updated_at: new Date().toISOString()
    }

    if (planId) {
      updateData.plan_id = parseInt(planId)
    }

    if (subscription) {
      updateData.current_period_start = new Date(subscription.current_period_start * 1000).toISOString()
      updateData.current_period_end = new Date(subscription.current_period_end * 1000).toISOString()
      updateData.stripe_price_id = subscription.items.data[0]?.price?.id
      updateData.cancel_at_period_end = subscription.cancel_at_period_end || false
    }

    const response = await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
        "Prefer": "return=representation"
      },
      body: JSON.stringify(updateData)
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(`Failed to update subscription: ${errorText}`)
    }

    console.log("[stripe-webhook] ✅ Subscription updated in database")

    // Record payment in payment_history
    if (subscription && session.amount_total) {
      await recordPayment({
        userId,
        subscriptionId: userId, // user_id is the subscription_id in our schema
        amount: session.amount_total / 100,
        currency: session.currency || "eur",
        status: "succeeded",
        stripe_payment_intent_id: session.payment_intent,
        stripe_invoice_id: subscription.latest_invoice,
        payment_method: "card",
        metadata: {
          checkout_session_id: session.id,
          subscription_id: subscriptionId
        }
      })
    }

    // Send confirmation email
    if (customer?.email) {
      await sendConfirmationEmail(customer.email, {
        type: "subscription_created",
        amount: session.amount_total ? (session.amount_total / 100) : 0,
        currency: session.currency || "eur",
        planName: planId ? `Plan ${planId}` : "Monthly Subscription"
      })
    }

    // Create notification
    const planName = planId ? `Plan ${planId}` : "Monthly Subscription"
    await createNotification(
      userId,
      "checkout_completed",
      userId, // System notification, fromUserId = userId
      `Your checkout has been completed successfully.`,
      { subscription_id: userId }
    )
    await createNotification(
      userId,
      "subscription_created",
      userId,
      `Your subscription has been created: ${planName}.`,
      { subscription_id: userId }
    )

    return { success: true, message: "Checkout session processed" }
  } catch (error) {
    console.error("[stripe-webhook] Error handling checkout session:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle subscription updated event
 */
async function handleSubscriptionUpdated(subscription: any) {
  console.log("[stripe-webhook] Handling subscription.updated...")
  
  try {
    const customerId = subscription.customer
    const subscriptionId = subscription.id

    // Get customer to find userId
    const customer = await stripe.customers.retrieve(customerId)
    const userId = customer.metadata?.supabase_user_id

    if (!userId) {
      console.warn("[stripe-webhook] ⚠️ No userId in customer metadata")
      return { success: false, error: "No userId in customer metadata" }
    }

    // Check if this is a scheduled cancellation (downgrade)
    const pendingPlanId = subscription.metadata?.pendingPlanId
    const isScheduledCancellation = subscription.cancel_at_period_end && pendingPlanId

    console.log("[stripe-webhook] Subscription update details:", {
      cancel_at_period_end: subscription.cancel_at_period_end,
      pendingPlanId: pendingPlanId,
      isScheduledCancellation: isScheduledCancellation
    })

    const updateData: any = {
      status: subscription.status === "active" ? "active" :
              subscription.status === "past_due" ? "past_due" :
              subscription.status === "canceled" ? "canceled" : "unpaid",
      current_period_start: new Date(subscription.current_period_start * 1000).toISOString(),
      current_period_end: new Date(subscription.current_period_end * 1000).toISOString(),
      stripe_price_id: subscription.items.data[0]?.price?.id,
      cancel_at_period_end: subscription.cancel_at_period_end || false,
      updated_at: new Date().toISOString()
    }

    if (subscription.canceled_at) {
      updateData.canceled_at = new Date(subscription.canceled_at * 1000).toISOString()
    }

    // If this is a scheduled downgrade, update pending plan info
    if (isScheduledCancellation) {
      updateData.pending_plan_id = parseInt(pendingPlanId)
      updateData.pending_change_at = new Date(subscription.current_period_end * 1000).toISOString()
      console.log("[stripe-webhook] Scheduled downgrade detected, will take effect at period end")
    }

    const response = await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
        "Prefer": "return=representation"
      },
      body: JSON.stringify(updateData)
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(`Failed to update subscription: ${errorText}`)
    }

    console.log("[stripe-webhook] ✅ Subscription updated")

    // Create notification based on subscription status
    if (subscription.status === "canceled" || subscription.status === "cancelled") {
      await createNotification(
        userId,
        "subscription_cancelled",
        userId,
        "Your subscription has been cancelled.",
        { subscription_id: userId }
      )
    } else if (subscription.status === "active") {
      await createNotification(
        userId,
        "subscription_updated",
        userId,
        "Your subscription has been updated.",
        { subscription_id: userId }
      )
    } else if (subscription.status === "past_due" || subscription.status === "unpaid") {
      await createNotification(
        userId,
        "subscription_expired",
        userId,
        "Your subscription has expired. Please update your payment method.",
        { subscription_id: userId }
      )
    }

    return { success: true, message: "Subscription updated" }
  } catch (error) {
    console.error("[stripe-webhook] Error handling subscription update:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle subscription deleted event
 */
async function handleSubscriptionDeleted(subscription: any) {
  console.log("[stripe-webhook] Handling subscription.deleted...")
  
  try {
    const customerId = subscription.customer
    const customer = await stripe.customers.retrieve(customerId)
    const userId = customer.metadata?.supabase_user_id

    if (!userId) {
      return { success: false, error: "No userId in customer metadata" }
    }

    // Check if this was a scheduled downgrade
    const pendingPlanId = subscription.metadata?.pendingPlanId
    const isScheduledDowngrade = pendingPlanId && subscription.metadata?.changeType === 'downgrade'

    console.log("[stripe-webhook] Subscription deletion details:", {
      pendingPlanId: pendingPlanId,
      isScheduledDowngrade: isScheduledDowngrade
    })

    if (isScheduledDowngrade) {
      // This was a scheduled downgrade - create new subscription with lower tier
      console.log("[stripe-webhook] Processing scheduled downgrade...")

      // M-4: re-validate the pending plan id at provisioning time. The id rode in
      // through Stripe metadata; treat it as untrusted here too (defense in depth —
      // even though update-subscription now validates on write). Require a positive
      // integer id.
      const pendingPlanIdInt = Number(pendingPlanId)
      if (!Number.isInteger(pendingPlanIdInt) || pendingPlanIdInt <= 0) {
        console.warn("[stripe-webhook] ⚠️ Invalid pendingPlanId, falling through to cancellation:", pendingPlanId)
      } else {
      // Get plan details from database (target + the user's CURRENT plan for the
      // downgrade-legitimacy check).
      const planResponse = await fetch(`${supabaseClient.url}/rest/v1/subscription_plans?id=eq.${pendingPlanIdInt}&select=*`, {
        method: "GET",
        headers: {
          "Content-Type": "application/json",
          "apikey": supabaseClient.key,
          "Authorization": `Bearer ${supabaseClient.key}`,
        },
      })

      // Resolve the user's CURRENT plan so we can assert the target is genuinely
      // cheaper (a real downgrade) and not an escalation slipped in via metadata.
      const currentSubResponse = await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}&select=plan_id`, {
        method: "GET",
        headers: {
          "apikey": supabaseClient.key,
          "Authorization": `Bearer ${supabaseClient.key}`,
        },
      })
      let currentPlan: any = null
      if (currentSubResponse.ok) {
        const subs = await currentSubResponse.json()
        const currentPlanId = subs?.[0]?.plan_id
        if (currentPlanId) {
          const curPlanResp = await fetch(`${supabaseClient.url}/rest/v1/subscription_plans?id=eq.${currentPlanId}&select=*`, {
            method: "GET",
            headers: {
              "apikey": supabaseClient.key,
              "Authorization": `Bearer ${supabaseClient.key}`,
            },
          })
          if (curPlanResp.ok) {
            const curPlans = await curPlanResp.json()
            currentPlan = curPlans && curPlans.length > 0 ? curPlans[0] : null
          }
        }
      }

      if (planResponse.ok) {
        const plans = await planResponse.json()
        const newPlan = plans && plans.length > 0 ? plans[0] : null

        // M-4: only provision when the target is active, has a Stripe price, and is
        // a TRUE downgrade (strictly cheaper than the current plan). Anything else
        // falls through to a plain cancellation rather than re-provisioning onto a
        // pricier/inactive/mis-priced plan.
        const isLegitDowngrade = !!newPlan
          && newPlan.is_active === true
          && !!newPlan.stripe_price_id
          && typeof newPlan.price_cents === "number"
          && (!currentPlan
              || (typeof currentPlan.price_cents === "number"
                  && newPlan.price_cents < currentPlan.price_cents))

        if (isLegitDowngrade) {
          // Create new subscription with downgraded plan
          const newSubscription = await stripe.subscriptions.create({
            customer: customerId,
            items: [{ price: newPlan.stripe_price_id }],
            metadata: {
              userId: userId,
              planId: pendingPlanId,
              changeType: 'downgrade_completed'
            }
          })

          console.log("[stripe-webhook] ✅ New subscription created for downgrade:", newSubscription.id)

          // Update database with new subscription (NEW OPTIMAL SCHEMA)
          const updateData = {
            status: "active",
            plan_id: parseInt(pendingPlanId),
            stripe_subscription_id: newSubscription.id,
            stripe_price_id: newPlan.stripe_price_id,
            current_period_start: new Date(newSubscription.current_period_start * 1000).toISOString(),
            current_period_end: new Date(newSubscription.current_period_end * 1000).toISOString(),
            cancel_at_period_end: newSubscription.cancel_at_period_end || false,
            pending_plan_id: null,
            pending_change_at: null,
            updated_at: new Date().toISOString()
          }

          const response = await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}`, {
            method: "PATCH",
            headers: {
              "Content-Type": "application/json",
              "apikey": supabaseClient.key,
              "Authorization": `Bearer ${supabaseClient.key}`,
              "Prefer": "return=representation"
            },
            body: JSON.stringify(updateData)
          })

          if (!response.ok) {
            throw new Error(`Failed to update subscription: ${await response.text()}`)
          }

          console.log("[stripe-webhook] ✅ Downgrade completed, new subscription active")
          return { success: true, message: "Scheduled downgrade completed" }
        } else {
          console.warn("[stripe-webhook] ⚠️ Pending plan invalid (inactive, missing Stripe price, or not a true downgrade), marking as cancelled")
        }
      }
      } // end M-4 positive-integer guard (else branch)
    }

    // Regular cancellation (not a scheduled downgrade)
    const updateData = {
      status: "canceled",
      canceled_at: new Date().toISOString(),
      pending_plan_id: null,
      pending_change_at: null,
      updated_at: new Date().toISOString()
    }

    const response = await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
        "Prefer": "return=representation"
      },
      body: JSON.stringify(updateData)
    })

    if (!response.ok) {
      throw new Error(`Failed to update subscription: ${await response.text()}`)
    }

    console.log("[stripe-webhook] ✅ Subscription cancelled")
    return { success: true, message: "Subscription cancelled" }
  } catch (error) {
    console.error("[stripe-webhook] Error handling subscription deletion:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle invoice payment succeeded
 * Records payment and sends invoice email
 */
async function handleInvoicePaymentSucceeded(invoice: any) {
  console.log("[stripe-webhook] Handling invoice.payment_succeeded...")
  
  try {
    const customerId = invoice.customer
    const subscriptionId = invoice.subscription
    const amount = invoice.amount_paid / 100
    const currency = invoice.currency

    // Get customer to find userId
    const customer = await stripe.customers.retrieve(customerId)
    const userId = customer.metadata?.supabase_user_id

    if (!userId) {
      return { success: false, error: "No userId in customer metadata" }
    }

    // Record payment
    await recordPayment({
      userId,
      subscriptionId: userId,
      amount,
      currency,
      status: "succeeded",
      stripe_invoice_id: invoice.id,
      stripe_payment_intent_id: invoice.payment_intent,
      payment_method: "card",
      metadata: {
        invoice_id: invoice.id,
        subscription_id: subscriptionId
      }
    })

    // Payment already recorded in payment_history table - no need to update subscription
    // The subscription status is managed by subscription.updated webhook events

    // Send invoice email
    if (customer.email) {
      await sendConfirmationEmail(customer.email, {
        type: "invoice_paid",
        amount,
        currency,
        invoiceId: invoice.id,
        invoiceUrl: invoice.hosted_invoice_url
      })
    }

    // Get payment record ID for notification
    const paymentRecordResponse = await fetch(`${supabaseClient.url}/rest/v1/payment_history?user_id=eq.${userId}&stripe_invoice_id=eq.${invoice.id}&order=created_at.desc&limit=1`, {
      headers: {
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`
      }
    })
    const paymentRecords = await paymentRecordResponse.json()
    const paymentId = paymentRecords?.[0]?.id || null

    // Create notifications
    await createNotification(
      userId,
      "invoice_paid",
      userId,
      `Your invoice has been paid: ${formatAmount(amount, currency)}.`,
      { payment_id: paymentId, subscription_id: userId, invoice_id: invoice.id }
    )
    await createNotification(
      userId,
      "payment_succeeded",
      userId,
      `Your payment was successful: ${formatAmount(amount, currency)}.`,
      { payment_id: paymentId, subscription_id: userId }
    )

    console.log("[stripe-webhook] ✅ Invoice payment recorded")
    return { success: true, message: "Invoice payment processed" }
  } catch (error) {
    console.error("[stripe-webhook] Error handling invoice payment:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle invoice payment failed
 */
async function handleInvoicePaymentFailed(invoice: any) {
  console.log("[stripe-webhook] Handling invoice.payment_failed...")
  
  try {
    const customerId = invoice.customer
    const customer = await stripe.customers.retrieve(customerId)
    const userId = customer.metadata?.supabase_user_id

    if (!userId) {
      return { success: false, error: "No userId in customer metadata" }
    }

    // Record failed payment
    await recordPayment({
      userId,
      subscriptionId: userId,
      amount: invoice.amount_due / 100,
      currency: invoice.currency,
      status: "failed",
      stripe_invoice_id: invoice.id,
      payment_method: "card",
      metadata: {
        invoice_id: invoice.id,
        failure_reason: invoice.last_payment_error?.message
      }
    })

    // Update subscription status to past_due
    await fetch(`${supabaseClient.url}/rest/v1/subscriptions?user_id=eq.${userId}`, {
      method: "PATCH",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`
      },
      body: JSON.stringify({
        status: "past_due",
        updated_at: new Date().toISOString()
      })
    })

    // Send payment failed email
    if (customer.email) {
      await sendConfirmationEmail(customer.email, {
        type: "payment_failed",
        amount: invoice.amount_due / 100,
        currency: invoice.currency,
        invoiceId: invoice.id
      })
    }

    // Get payment record ID for notification
    const paymentRecordResponse = await fetch(`${supabaseClient.url}/rest/v1/payment_history?user_id=eq.${userId}&stripe_invoice_id=eq.${invoice.id}&order=created_at.desc&limit=1`, {
      headers: {
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`
      }
    })
    const paymentRecords = await paymentRecordResponse.json()
    const paymentId = paymentRecords?.[0]?.id || null

    // Create notification
    await createNotification(
      userId,
      "payment_failed",
      userId,
      `Your payment failed. Please update your payment method to continue your subscription.`,
      { payment_id: paymentId, subscription_id: userId, invoice_id: invoice.id }
    )

    console.log("[stripe-webhook] ✅ Payment failure recorded")
    return { success: true, message: "Payment failure processed" }
  } catch (error) {
    console.error("[stripe-webhook] Error handling payment failure:", error)
    return { success: false, error: error.message }
  }
}

/**
 * Handle payment intent succeeded
 */
async function handlePaymentIntentSucceeded(paymentIntent: any) {
  console.log("[stripe-webhook] Handling payment_intent.succeeded...")
  // Payment intents are usually handled via invoice events
  // This is a fallback for direct payments
  return { success: true, message: "Payment intent processed" }
}

/**
 * Record payment in payment_history table
 */
async function recordPayment(paymentData: any) {
  try {
    console.log("[stripe-webhook] Recording payment:", {
      userId: paymentData.userId,
      amount: paymentData.amount,
      status: paymentData.status
    })

    const response = await fetch(`${supabaseClient.url}/rest/v1/payment_history`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
        "Prefer": "return=representation"
      },
      body: JSON.stringify({
        user_id: paymentData.userId,
        subscription_id: paymentData.subscriptionId,
        stripe_payment_intent_id: paymentData.stripe_payment_intent_id,
        stripe_invoice_id: paymentData.stripe_invoice_id,
        amount: paymentData.amount,
        currency: paymentData.currency,
        status: paymentData.status,
        payment_method: paymentData.payment_method,
        payment_date: new Date().toISOString(),
        metadata: paymentData.metadata || {}
      })
    })

    if (!response.ok) {
      const errorText = await response.text()
      throw new Error(`Failed to record payment: ${errorText}`)
    }

    console.log("[stripe-webhook] ✅ Payment recorded")
  } catch (error) {
    console.error("[stripe-webhook] Error recording payment:", error)
    throw error
  }
}

/**
 * Send confirmation email
 * Uses Supabase Edge Function or external email service
 */
async function sendConfirmationEmail(email: string, data: any) {
  try {
    console.log("[stripe-webhook] Sending email to:", email)
    
    // Option 1: Use Supabase Edge Function for emails (if you have one)
    // Option 2: Use external email service (SendGrid, Mailgun, etc.)
    // Option 3: Use Stripe's built-in email notifications (configured in Stripe Dashboard)
    
    // For now, we'll log the email that should be sent
    // You can implement actual email sending here
    console.log("[stripe-webhook] Email to send:", {
      to: email,
      type: data.type,
      subject: getEmailSubject(data.type),
      data: data
    })

    // TODO: Implement actual email sending
    // Example using Supabase Edge Function:
    // await fetch(`${supabaseClient.url}/functions/v1/send-email`, {
    //   method: "POST",
    //   headers: {
    //     "Content-Type": "application/json",
    //     "Authorization": `Bearer ${supabaseClient.key}`
    //   },
    //   body: JSON.stringify({
    //     to: email,
    //     subject: getEmailSubject(data.type),
    //     template: data.type,
    //     data: data
    //   })
    // })

    console.log("[stripe-webhook] ✅ Email queued (implementation needed)")
  } catch (error) {
    console.warn("[stripe-webhook] ⚠️ Error sending email:", error)
    // Don't fail the webhook if email fails
  }
}

/**
 * Get email subject based on type
 */
function getEmailSubject(type: string): string {
  const subjects: Record<string, string> = {
    subscription_created: "Welcome! Your subscription is active",
    invoice_paid: "Payment received - Invoice",
    payment_failed: "Payment failed - Action required"
  }
  return subjects[type] || "Money Tracker Notification"
}

/**
 * Get a short notification title from the notification type.
 * The notifications table has a NOT NULL `title` column; every notification
 * MUST supply one. Falls back to a generic title for unmapped types.
 */
function getNotificationTitle(type: string): string {
  const titles: Record<string, string> = {
    checkout_completed: "Checkout completed",
    subscription_created: "Subscription active",
    subscription_updated: "Subscription updated",
    subscription_cancelled: "Subscription cancelled",
    subscription_expired: "Subscription expired",
    invoice_paid: "Invoice paid",
    payment_succeeded: "Payment successful",
    payment_failed: "Payment failed"
  }
  return titles[type] || "Notification"
}

/**
 * Create a notification for a user
 * @param {string} userId - User ID
 * @param {string} type - Notification type
 * @param {string} fromUserId - User/system that triggered the notification (use userId for system notifications)
 * @param {string} message - Notification message
 * @param {Object} metadata - Optional metadata (payment_id, subscription_id, invoice_id)
 */
async function createNotification(
  userId: string,
  type: string,
  fromUserId: string,
  message: string,
  metadata: {
    payment_id?: number | null,
    subscription_id?: string | null,
    invoice_id?: string | null
  } = {}
) {
  try {
    console.log("[stripe-webhook] ========== CREATING NOTIFICATION ==========")
    console.log("[stripe-webhook] Notification details:", { 
      userId, 
      type, 
      fromUserId,
      messageLength: message?.length,
      hasPaymentId: !!metadata.payment_id,
      hasSubscriptionId: !!metadata.subscription_id,
      hasInvoiceId: !!metadata.invoice_id,
      metadata
    })

    // The notifications table has a NOT NULL `title` column and does NOT have
    // payment_id / subscription_id / invoice_id columns. Supply an explicit
    // title (derived from the type) and fold any id references into the existing
    // `data` JSONB column instead of writing nonexistent top-level columns.
    const data: Record<string, unknown> = {}
    if (metadata.payment_id) {
      data.payment_id = metadata.payment_id
      console.log("[stripe-webhook] Added payment_id to notification data:", metadata.payment_id)
    }
    if (metadata.subscription_id) {
      data.subscription_id = metadata.subscription_id
      console.log("[stripe-webhook] Added subscription_id to notification data:", metadata.subscription_id)
    }
    if (metadata.invoice_id) {
      data.invoice_id = metadata.invoice_id
      console.log("[stripe-webhook] Added invoice_id to notification data:", metadata.invoice_id)
    }

    const notificationData: any = {
      user_id: userId,
      type: type,
      from_user_id: fromUserId,
      title: getNotificationTitle(type),
      message: message,
      data: data,
      read: false
    }

    console.log("[stripe-webhook] Sending notification to database:", {
      url: `${supabaseClient.url}/rest/v1/notifications`,
      notificationDataKeys: Object.keys(notificationData)
    })

    const response = await fetch(`${supabaseClient.url}/rest/v1/notifications`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "apikey": supabaseClient.key,
        "Authorization": `Bearer ${supabaseClient.key}`,
        "Prefer": "return=representation"
      },
      body: JSON.stringify(notificationData)
    })

    if (!response.ok) {
      const errorText = await response.text()
      console.error("[stripe-webhook] ❌ Failed to create notification:", {
        status: response.status,
        statusText: response.statusText,
        error: errorText
      })
      return { success: false, error: errorText }
    }

    const notification = await response.json()
    console.log("[stripe-webhook] ✅ Notification created successfully:", {
      notificationId: notification[0]?.id,
      type: notification[0]?.type,
      userId: notification[0]?.user_id
    })
    console.log("[stripe-webhook] ========== NOTIFICATION CREATION COMPLETE ==========")
    return { success: true, notification: notification[0] }
  } catch (error) {
    console.error("[stripe-webhook] ========== NOTIFICATION CREATION ERROR ==========")
    console.error("[stripe-webhook] Exception details:", {
      errorMessage: error.message,
      errorStack: error.stack,
      errorName: error.name
    })
    return { success: false, error: error.message }
  }
}

