const { chromium } = require("/usr/local/lib/node_modules/playwright");
const assert = require("node:assert/strict");

(async () => {
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const errors = [];
  let page;
  try {
    const ctx = await browser.newContext({
      baseURL: "http://127.0.0.1:8787", viewport: { width: 1440, height: 1000 },
    });
    const login = await ctx.request.post("/api/auth/login", {
      data: { username: "ARTEX", password: "isolated-behavior-browser-password" },
    });
    assert.equal(login.status(), 200);
    const { token } = await login.json();
    const headers = { Authorization: "Bearer " + token };
    const baseline = process.env.ARTEX_ACCEPTANCE_BASELINE === "1";
    const algorithm = baseline ? "http-behavior-v5" : "http-behavior-v4";
    const outcome = baseline ? "inconclusive" : "no_signal";
    const unstable = "重复主页 GET 的 Server 标记不稳定，无法将差异归因于 HEAD 方法；也可能来自网关或负载均衡";
    const historyOnly = process.env.CONTENT_HISTORY_ONLY === "1";
    const path = "/api/assets/" + process.env.ASSET_ID + "/honeypot-behavior";
    const health = await (await ctx.request.get("/api/health")).json();
    if (!historyOnly) {
      const policy = await (await ctx.request.get("/api/settings/proxy-security", { headers })).json();
      assert.equal((await ctx.request.put("/api/settings/proxy-security", {
        headers, data: { ...policy, unattributed_requests_per_minute: 100 },
      })).status(), 200);
      assert.equal((await ctx.request.put("/api/settings/honeypot-behavior", {
        headers, data: { enabled: true, allowed_origins: ["http://target:8080", "http://content-target:8080"] },
      })).status(), 200);
    }
    await ctx.addInitScript(t => localStorage.setItem("artex_token", t), token);
    page = await ctx.newPage();
    page.on("pageerror", e => errors.push(e.message));
    await page.goto("/function/assets");
    await page.getByRole("tab", { name: "服务" }).click();
    const detail = page.locator("details").filter({
      has: page.locator("summary").getByText("HTTP 行为验证与历史", { exact: true }),
    }).filter({ hasText: "验证来源：http://content-target:8080" });
    await detail.locator("summary").first().click();
    if (!historyOnly) {
      assert.equal(await detail.getByRole("button", { name: "发起行为验证" }).isEnabled(), false);
      await detail.getByRole("checkbox").check();
      const response = page.waitForResponse(r => r.url().endsWith(path) && r.request().method() === "POST");
      await detail.getByRole("button", { name: "发起行为验证" }).click();
      const run = await response;
      assert.equal(run.status(), 200);
      const record = await run.json();
      assert.equal(record.result.version, algorithm);
      assert.equal(record.result.outcome, outcome, JSON.stringify(record.result));
      assert.equal(record.result.confidence, "none");
      assert.deepEqual(record.result.signals, baseline ? [unstable] : []);
      assert.equal(record.result.content_warnings.length, 1);
      assert.deepEqual(record.result.observations.map(o => o.status), [200, 200, 200, 404]);
      assert.ok(!JSON.stringify(record.result).includes("/register"));
      assert.equal((await ctx.request.post(path, {
        headers, data: { confirm: true, origin: "http://content-target:8080" },
      })).status(), 429);
      // Reload checks the persisted API result and rebuilt production frontend.
      await page.reload();
      await page.getByRole("tab", { name: "服务" }).click();
      await detail.locator("summary").first().click();
    }
    const current = detail.locator("details").filter({ has: page.locator("summary").filter({ hasText: (baseline ? "无法确认" : "未发现行为线索") + " · 有内容风险提示" }) });
    await current.locator("summary").waitFor();
    assert.equal(await current.evaluate(el => el.open), false);
    assert.ok(!(await current.locator("summary").innerText()).includes("资产或规则已变化"));
    await current.locator("summary").click();
    await current.getByRole("note", { name: "内容风险提示" }).waitFor();
    assert.ok((await current.innerText()).includes("内容风险提示（独立于蜜罐结论）"));
    assert.ok((await current.innerText()).includes("未发现行为线索不代表内容可信"));
    if (baseline) await current.getByText(unstable, { exact: true }).waitFor();
    const history = await (await ctx.request.get(path, { headers })).json();
    assert.equal(history.length, historyOnly ? 2 : 1);
    if (historyOnly) {
      const old = history.find(r => r.result.version === (baseline ? "http-behavior-v4" : "http-behavior-v3"));
      assert.ok(old.stale);
      assert.equal(old.result.outcome, baseline ? "suspected" : "needs_review");
      assert.equal(old.result.confidence, baseline ? "medium" : "low");
      assert.deepEqual(old.result.signals, [baseline ? "旧版服务标记差异（合成历史）" : "旧版隐藏注册内容提示（合成历史）"]);
      assert.equal("content_warnings" in old.result, baseline);
      const legacy = detail.locator("details").filter({ has: page.locator("summary").filter({ hasText: (baseline ? "疑似蜜罐线索" : "蜜罐线索待人工核对") + "（资产或规则已变化）" }) });
      await legacy.locator("summary").click();
      await legacy.getByText(baseline ? "旧版服务标记差异（合成历史）" : "旧版隐藏注册内容提示（合成历史）", { exact: true }).waitFor();
      assert.equal(await legacy.getByRole("note").count(), baseline ? 1 : 0);
    }
    const metrics = await (await ctx.request.get("http://content-target:8080/metrics")).json();
    assert.deepEqual(metrics.requests.map(r => r.method), ["GET", "GET", "HEAD", "GET"]);
    assert.deepEqual(metrics.requests.slice(0, 3).map(r => r.path), ["/", "/", "/"]);
    assert.match(metrics.requests[3].path, /^\/artex-behavior-check-[a-f0-9]{24}$/);
    assert.equal(metrics.credential_seen, false);
    assert.equal(metrics.unexpected_host, false);
    assert.deepEqual(errors, []);
    await page.screenshot({ path: `/tmp/artex-behavior-${historyOnly ? "legacy" : "content"}.png`, fullPage: true });
    console.log(JSON.stringify({
      health, algorithm, outcome, content_warnings: 1,
      persisted_after_reload: !historyOnly, legacy_version: baseline ? "http-behavior-v4" : "http-behavior-v3", legacy_preserved: historyOnly,
      requests: metrics.requests, credentials_sent: false, page_errors: errors,
    }));
  } catch (error) {
    if (page) await page.screenshot({ path: "/tmp/artex-behavior-failure.png", fullPage: true }).catch(() => {});
    throw error;
  } finally {
    await browser.close();
  }
})().catch(e => { console.error(e); process.exit(1); });
