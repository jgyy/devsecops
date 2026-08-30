import express from "express";
import { vulnerableRouter } from "./routes/vulnerable";

export const app = express();

app.use(vulnerableRouter);

app.get("/health", (_req, res) => {
  res.status(200).json({ status: "ok" });
});
