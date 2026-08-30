// DEMO ONLY — NOT A REAL CREDENTIAL. This is a fabricated, Stripe-key-shaped
// string (see "amplehardcodedkeyDoNotUse" spelled out in the value itself)
// used solely to seed CWE-798 (hardcoded credential) for this repo's SAST
// pipeline demo — the Semgrep `p/default` ruleset's secret-detection rule
// needs a value shaped like a real vendor key to actually flag it. It has
// never been a live Stripe key and grants no access to anything.
export const STRIPE_API_KEY = "sk_live_51NcE9xamplehardcodedkeyDoNotUse00";
