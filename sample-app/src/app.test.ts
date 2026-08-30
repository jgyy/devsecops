import { describe, it, expect } from "vitest";
import request from "supertest";
import { app, bootInfo } from "./app";
import { STRIPE_API_KEY } from "./config";

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

describe("GET /file (intentionally vulnerable: path traversal)", () => {
  it("serves the intended file by default", async () => {
    const res = await request(app).get("/file");
    expect(res.status).toBe(200);
    expect(res.body.content).toContain("sample notes");
  });

  it("reads files outside the intended data directory", async () => {
    const res = await request(app)
      .get("/file")
      .query({ name: "../package.json" });
    expect(res.status).toBe(200);
    expect(res.body.content).toContain('"name": "sample-app"');
  });
});

describe("config", () => {
  it("exposes a Stripe API key in the expected format", () => {
    expect(STRIPE_API_KEY).toMatch(/^sk_live_/);
  });
});

describe("dependencies (intentionally vulnerable: lodash@4.17.15, CVE-2020-8203)", () => {
  it("exercises the vulnerable zipObjectDeep function at boot", () => {
    expect(bootInfo).toEqual({ service: "sample-app", status: "ready" });
  });
});
