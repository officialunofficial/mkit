// test/spammer-auth.test.ts
//
// Unit tests for control-auth.ts's pure helpers — the `/control` auth gate
// (`isAuthorized`/`timingSafeEqual`) and action resolution (`resolveAction`).
// These are the security-critical pieces of the DO's control surface (the
// whole kill-switch/dormant-by-default story depends on an unset
// CONTROL_TOKEN failing closed, and on a malformed request never slipping
// past the auth check) and were previously verified only by manual
// wrangler-dev smoke tests, not an automated suite. Plain Request/URL
// objects, no wasm, no DO storage, no `cloudflare:workers` import (that's
// exactly why these live in control-auth.ts and not spammer.ts — see that
// file's doc comment) — runs in the "unit" vitest project.

import { describe, expect, it } from "vitest";
import { isAuthorized, jsonResponse, resolveAction, timingSafeEqual } from "../src/control-auth";

describe("spammer.ts — timingSafeEqual", () => {
  it("returns true for identical strings", () => {
    expect(timingSafeEqual("same-token", "same-token")).toBe(true);
  });

  it("returns false for different strings of the same length", () => {
    expect(timingSafeEqual("aaaaaaaaaa", "aaaaaaaaab")).toBe(false);
  });

  it("returns false for different-length strings without throwing", () => {
    expect(timingSafeEqual("short", "much-longer-string")).toBe(false);
  });

  it("returns true for two empty strings", () => {
    expect(timingSafeEqual("", "")).toBe(true);
  });
});

function requestWithAuth(header?: string): Request {
  const headers = new Headers();
  if (header !== undefined) headers.set("Authorization", header);
  return new Request("https://example.invalid/control", { headers });
}

describe("spammer.ts — isAuthorized", () => {
  it("accepts a well-formed Bearer header matching the expected token", () => {
    expect(isAuthorized(requestWithAuth("Bearer secret-token"), "secret-token")).toBe(true);
  });

  it("rejects a Bearer header with the wrong token", () => {
    expect(isAuthorized(requestWithAuth("Bearer wrong-token"), "secret-token")).toBe(false);
  });

  it("rejects when the Authorization header is missing entirely", () => {
    expect(isAuthorized(requestWithAuth(undefined), "secret-token")).toBe(false);
  });

  it("rejects a header that isn't the Bearer scheme", () => {
    expect(isAuthorized(requestWithAuth("Basic dXNlcjpwYXNz"), "secret-token")).toBe(false);
  });

  it("rejects EVERY request when expected is undefined (unset CONTROL_TOKEN fails closed)", () => {
    expect(isAuthorized(requestWithAuth("Bearer anything-at-all"), undefined)).toBe(false);
    expect(isAuthorized(requestWithAuth(undefined), undefined)).toBe(false);
  });

  it("rejects an empty-string expected token too (not just undefined)", () => {
    // `!expected` also short-circuits an empty-string secret — belt-and-braces
    // against a misconfigured-but-defined empty CONTROL_TOKEN ever passing.
    expect(isAuthorized(requestWithAuth("Bearer "), "")).toBe(false);
  });
});

describe("spammer.ts — resolveAction", () => {
  it("prefers the ?action= query param when present", async () => {
    const request = new Request("https://example.invalid/control?action=enable", { method: "POST" });
    expect(await resolveAction(request, new URL(request.url))).toBe("enable");
  });

  it("falls back to a POST JSON body's action field when there's no query param", async () => {
    const request = new Request("https://example.invalid/control", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "disable" }),
    });
    expect(await resolveAction(request, new URL(request.url))).toBe("disable");
  });

  it("query param wins even when a POST body also has an action", async () => {
    const request = new Request("https://example.invalid/control?action=status", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ action: "enable" }),
    });
    expect(await resolveAction(request, new URL(request.url))).toBe("status");
  });

  it("defaults to status for a bare GET with no query param", async () => {
    const request = new Request("https://example.invalid/control");
    expect(await resolveAction(request, new URL(request.url))).toBe("status");
  });

  it("defaults to status when the POST body is invalid JSON, without throwing", async () => {
    const request = new Request("https://example.invalid/control", {
      method: "POST",
      body: "not json",
    });
    expect(await resolveAction(request, new URL(request.url))).toBe("status");
  });

  it("defaults to status when the POST body is valid JSON but has no string action field", async () => {
    const request = new Request("https://example.invalid/control", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ notAction: 42 }),
    });
    expect(await resolveAction(request, new URL(request.url))).toBe("status");
  });
});

describe("spammer.ts — jsonResponse", () => {
  it("serializes the body as JSON with the given status and content-type header", async () => {
    const response = jsonResponse({ enabled: true, room: "spammer-test" }, 200);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json");
    expect(await response.json()).toEqual({ enabled: true, room: "spammer-test" });
  });

  it("passes through a non-200 status", () => {
    expect(jsonResponse({ error: "unauthorized" }, 401).status).toBe(401);
  });
});
