import assert from "node:assert/strict";
import { test } from "node:test";
import { authenticatedFetch, clearAccessToken, ensureSession, logoutSession, saveAccessToken } from "./session.ts";

const values = new Map<string, string>();
const storage = {
  getItem: (k: string) => values.get(k) ?? null,
  setItem: (k: string, v: string) => {
    values.set(k, v);
  },
  removeItem: (k: string) => {
    values.delete(k);
  },
};
Object.defineProperty(globalThis, "localStorage", { value: storage });
Object.defineProperty(globalThis, "window", { value: { location: { href: "" } } });
Object.defineProperty(globalThis, "document", { value: { cookie: "" } });
Object.defineProperty(globalThis, "location", { value: { protocol: "http:", pathname: "/function/tasks" } });
const access = (exp: number, tag = "") => `a.${Buffer.from(JSON.stringify({ exp, tag })).toString("base64url")}.b`;
const fresh = () => access(Date.now() / 1000 + 900);
const reply = (status: number, body: unknown = {}) =>
  new Response(JSON.stringify(body), { status, headers: { "Content-Type": "application/json" } });

test("parallel requests share one refresh and preserve upload body", async () => {
  clearAccessToken();
  let count = 0;
  let calls = 0;
  const body = new FormData();
  body.append("file", new Blob(["data"]), "test.txt");
  globalThis.fetch = async (url, init) => {
    if (url === "/api/auth/refresh") {
      count++;
      await new Promise((r) => setTimeout(r, 10));
      return reply(200, { token: fresh() });
    }
    calls++;
    assert.equal(init?.body, body);
    assert.match(new Headers(init?.headers).get("Authorization")!, /^Bearer /);
    return reply(200);
  };
  await Promise.all([
    authenticatedFetch("/api/upload", { method: "POST", body }),
    authenticatedFetch("/api/upload", { method: "POST", body }),
  ]);
  assert.equal(count, 1);
  assert.equal(calls, 2);
});
test("401 retries once with rotated access, including SSE ticket calls", async () => {
  saveAccessToken(fresh());
  let refresh = 0;
  let calls = 0;
  globalThis.fetch = async (url) => {
    if (url === "/api/auth/refresh") {
      refresh++;
      return reply(200, { token: fresh() });
    }
    return reply(++calls === 1 ? 401 : 200);
  };
  assert.equal(
    (await authenticatedFetch("/api/sse-ticket", { method: "POST", body: '{"path":"/api/logs/stream"}' })).status,
    200,
  );
  assert.equal(refresh, 1);
  assert.equal(calls, 2);
});
test("temporary outage keeps credentials; revocation clears them", async () => {
  saveAccessToken(access(1));
  globalThis.fetch = async () => reply(503);
  await assert.rejects(ensureSession(), /暂时不可用/);
  assert.ok(storage.getItem("artex_token"));
  globalThis.fetch = async () => reply(401);
  assert.equal(await ensureSession(), false);
  assert.equal(storage.getItem("artex_token"), null);
});
test("logout waits for in-flight refresh and cannot restore access", async () => {
  clearAccessToken();
  let finish!: (r: Response) => void;
  let logout = false;
  globalThis.fetch = async (url) => {
    if (url === "/api/auth/refresh")
      return new Promise((resolve) => {
        finish = resolve;
      });
    logout = true;
    return reply(200);
  };
  const pending = ensureSession();
  await Promise.resolve();
  const exiting = logoutSession();
  finish(reply(200, { token: fresh() }));
  await exiting;
  assert.equal(await pending, false);
  assert.equal(logout, true);
  assert.equal(storage.getItem("artex_token"), null);
});
