import { describe, it, expect } from "vitest";
import request from "supertest";
import { app } from "./app";

describe("GET /health", () => {
  it("returns ok status", async () => {
    const res = await request(app).get("/health");
    expect(res.status).toBe(200);
    expect(res.body).toEqual({ status: "ok" });
  });
});

describe("GET /run (intentionally vulnerable: OS command injection)", () => {
  it("executes attacker-controlled shell commands", async () => {
    const res = await request(app)
      .get("/run")
      .query({ cmd: "echo injection-proof-12345" });
    expect(res.status).toBe(200);
    expect(res.body.output).toBe("injection-proof-12345");
  });
});
