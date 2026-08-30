// Intentionally vulnerable: a hardcoded credential (CWE-798), seeded so the
// SAST pipeline's `p/secrets` Semgrep ruleset has a real finding to catch.
export const STRIPE_API_KEY = "sk_live_51NcE9xamplehardcodedkeyDoNotUse00";
