# WP Full Stripe Free — Broken Access Control via AJAX vs REST Handler Divergence

## Plugin
- **Name:** WP Full Stripe Free (wp-full-stripe-free)
- **Version:** 8.5.3
- **Installs:** 9,000
- **Path:** `/tmp/woo_deep/wp-full-stripe-free/`

## Vulnerability
- **Type:** Broken Access Control (CWE-639)
- **File:** `includes/wpfs-customer-portal-service.php:2045-2085`
- **Handler:** `wp_ajax_nopriv_wp_full_stripe_cancel_my_subscription` → `handleSubscriptionCancellationRequest()`
- **Severity:** High

## Root Cause

The plugin registers BOTH a nopriv AJAX handler AND a REST API route for subscription management. The REST API handler validates that the subscription belongs to the authenticated customer. The AJAX handler does NOT.

### Vulnerable AJAX Handler (line 2045)
```php
public function handleSubscriptionCancellationRequest()
{
    // ...
    $subscriptionIdsToCancel = isset($_POST[self::PARAM_WPFS_SUBSCRIPTION_ID]) ? $_POST[self::PARAM_WPFS_SUBSCRIPTION_ID] : null;
    // ...
    $cardUpdateSession = $this->findCustomerPortalSessionByHash($cardUpdateSessionHash);
    if (!is_null($cardUpdateSession) && $this->isConfirmed($cardUpdateSession)) {
        $stripeCustomer = $this->stripe->retrieveCustomer($cardUpdateSession->stripeCustomerId);
        if (isset($stripeCustomer)) {
            foreach ($subscriptionIdsToCancel as $subscriptionId) {
                // NO ownership check! $subscriptionId is arbitrary user input
                $this->cancelSubscriptionInDatabase($subscriptionId);
                $this->stripe->cancelSubscription($stripeCustomer->id, $subscriptionId, $cancelAtPeriodEnd);
            }
        }
    }
}
```

### Secure REST API Handler (line 2158) — Same Operation, Proper Authorization
```php
public function handleSubscriptionUpdateRequest(WP_REST_Request $request)
{
    $cardUpdateSession = $this->getAuthenticatedCardUpdateSession();
    // ...
    if ('cancel' === $updatedSubscription['action']) {
        $subscription = $this->stripe->retrieveSubscriptionWithParams($stripeSubscriptionId, $subscriptionParams);
        $subscriptionCustomerId = $subscription->customer;
        // PROPER ownership validation:
        if ($subscriptionCustomerId !== $cardUpdateSession->stripeCustomerId) {
            return new WP_Error('wpfs_customer_portal_forbidden', __('Unauthorized'), ['status' => 403]);
        }
        $this->db->cancelSubscriptionByStripeSubscriptionId($stripeSubscriptionId);
        $this->stripe->cancelSubscription($cardUpdateSession->stripeCustomerId, $stripeSubscriptionId, $cancelAtPeriodEnd);
    }
}
```

## Key Observation

The developer implemented proper authorization in the REST handler (`handleSubscriptionUpdateRequest`, line 2183) but forgot it in the AJAX handler (`handleSubscriptionCancellationRequest`, line 2060). Both handlers:
- Authenticate via the same cookie-based session (`findSessionCookieValue()`)
- Accept subscription IDs from user input
- Call the same database and Stripe cancellation methods

The ONLY difference is the ownership check. This is a systematic pattern: when a plugin has both AJAX and REST paths for the same operation, the REST path often gets more security attention.

## Exploit Steps

1. **Create session:** POST to `admin-ajax.php` with `action=wp_full_stripe_create_card_update_session` and `emailAddress=attacker@example.com`
2. **Confirm session:** POST to `admin-ajax.php` with `action=wp_full_stripe_validate_security_code` and the security code received via email
3. **Cancel arbitrary subscription:** POST to `admin-ajax.php` with:
   - `action=wp_full_stripe_cancel_my_subscription`
   - `wpfs-subscription-id[]=sub_XXXXXXXXX` (any subscription ID on the Stripe account)
   - Cookie: `WPFS_CARD_UPDATE_SESSION_ID=<session_hash>`

The attacker's session is linked to their own Stripe customer, but the subscription IDs are not validated against that customer. Any subscription on the connected Stripe account can be cancelled.

## Additional Findings (Not Exploitable)

### Missing Nonce on Payment Charge Handlers
The nopriv AJAX handlers for payment processing (`fullstripe_inline_payment_charge`, `fullstripe_inline_subscription_charge`, `fullstripe_checkout_payment_charge`, etc.) extract a nonce field (`wpfs-nonce`) via `bind()` but do NOT verify it server-side. `wp_verify_nonce` only appears in admin handlers and `update_failed_payment_status`. However, actual payment requires Stripe-side validation (PaymentMethod via Stripe.js), so the practical impact is limited — the nonce is returned in the response but never validated.

### Unprepared SQL Queries (40 total)
All in `wpfs-patcher.php` (activation/update migrations), `wpfs-database.php` (admin CRUD with hardcoded values), or `wpfs-tables.php` (admin table rendering). None reachable from nopriv handlers with user-controlled input. `cancelSubscriptionByStripeSubscriptionId()` (line 1610) properly uses `$wpdb->prepare()`.

## Patchstack Compliance
- ✅ Unauthenticated (attacker needs a session, obtainable via the plugin's own email flow)
- ✅ 9,000 installs (≥ 1,000)
- ✅ Broken access control / auth bypass — accepted vuln type
- ✅ Concrete impact: arbitrary subscription cancellation
- ✅ CVSS ~7.5+ (confidentiality N/A, integrity High, availability High)

## Fix
Add ownership validation before cancellation, matching the REST API handler:
```php
foreach ($subscriptionIdsToCancel as $subscriptionId) {
    $subscription = $this->stripe->retrieveSubscriptionWithParams($subscriptionId, ['expand' => ['items.data.price']]);
    $subscriptionCustomerId = (is_object($subscription) && isset($subscription->customer)) ? $subscription->customer : null;
    if ($subscriptionCustomerId !== $cardUpdateSession->stripeCustomerId) {
        continue; // or return error
    }
    $this->cancelSubscriptionInDatabase($subscriptionId);
    $this->stripe->cancelSubscription($stripeCustomer->id, $subscriptionId, $cancelAtPeriodEnd);
}
```
