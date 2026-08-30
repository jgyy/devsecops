import express from "express";
import { vulnerableRouter } from "./routes/vulnerable";
import { STRIPE_API_KEY } from "./config";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});

console.log(`sample-app booting (stripe key configured: ${STRIPE_API_KEY.slice(0, 7)}...)`);
