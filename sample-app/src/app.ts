import express from "express";
import { zipObjectDeep } from "lodash";
import { vulnerableRouter } from "./routes/vulnerable";
import { STRIPE_API_KEY } from "./config";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

// CVE-2020-8203: sample-app pins lodash@4.17.15 as the seeded finding for
// the SCA gate. zipObjectDeep is the exact function that CVE affects —
// referenced here so the dependency is genuinely exercised at boot, not
// just declared in package.json.
export const bootInfo = zipObjectDeep(
  ["service", "status"],
  ["sample-app", "ready"],
) as Record<string, string>;

console.log(
  `sample-app booting (stripe key configured: ${STRIPE_API_KEY.slice(0, 7)}..., ${JSON.stringify(bootInfo)})`,
);
