const { chromium } = require("/usr/local/lib/node_modules/playwright");
const assert = require("node:assert/strict");
const http = require("node:http");

// Explicit loopback proxy; target is only the compose network's synthetic service.
async function throughProxy(path, headers = {}) {
	return new Promise((resolve, reject) => {
		const request = http.request(
			{
				hostname: "127.0.0.1",
				port: 8788,
				method: "GET",
				path: "http://target:8080/" + path,
				headers: { Host: "target:8080", ...headers },
				agent: false,
			},
			(response) => {
				response.resume();
				response.on("end", () => resolve(response.statusCode));
				response.on("error", reject);
			},
		);
		request.setTimeout(5000, () =>
			request.destroy(new Error("proxy request timeout")),
		);
		request.on("error", reject);
		request.end();
	});
}
(async () => {
	const browser = await chromium.launch({
		headless: true,
		args: ["--no-sandbox"],
	});
	let page;
	const errors = [];
	try {
		const ctx = await browser.newContext({
			baseURL: "http://127.0.0.1:8787",
			viewport: { width: 1440, height: 1000 },
		});
		page = await ctx.newPage();
		page.on("pageerror", (e) => errors.push(e.message));
		const authStatus = await (await ctx.request.get("/api/auth/status")).json();
		assert.equal(
			authStatus.initialized,
			false,
			"acceptance requires a fresh isolated database",
		);
		const login = await ctx.request.post("/api/auth/init", {
			data: { password: "isolated-behavior-browser-password" },
		});
		assert.equal(login.status(), 200);
		const { token } = await login.json();
		const headers = { Authorization: "Bearer " + token };
		const upstreamSaved = await ctx.request.put("/api/settings", {
			headers,
			data: { global_proxy: "http://probe:isolated-proxy-only@upstream:8081" },
		});
		assert.equal(upstreamSaved.status(), 200);
		// Install the test session before hydration/auth guards can redirect.
		await ctx.addInitScript((t) => {
			if (!localStorage.getItem("artex_token"))
				localStorage.setItem("artex_token", t);
		}, token);
		await page.goto("/system/settings");
		const honey = page
			.locator('[data-slot="card"]')
			.filter({ has: page.getByText("HTTP 蜜罐行为验证", { exact: true }) });
		await honey.getByText("启用人工行为验证", { exact: true }).waitFor();
		await honey.getByRole("switch").click();
		await honey.getByLabel("行为验证授权来源").fill("http://target:8080");
		const saved = page.waitForResponse(
			(r) =>
				r.url().endsWith("/api/settings/honeypot-behavior") &&
				r.request().method() === "PUT",
		);
		await honey.getByRole("button", { name: "保存行为验证设置" }).click();
		assert.equal((await saved).status(), 200);
		const cfg = await (
			await ctx.request.get("/api/settings/honeypot-behavior", { headers })
		).json();
		assert.equal(cfg.enabled, true);
		assert.deepEqual(cfg.allowed_origins, ["http://target:8080"]);
		const proxy = page
			.locator('[data-slot="card"]')
			.filter({ has: page.getByText("代理安全", { exact: true }) });
		await proxy.getByLabel("每任务每分钟请求数", { exact: true }).fill("13");
		const psaved = page.waitForResponse(
			(r) =>
				r.url().endsWith("/api/settings/proxy-security") &&
				r.request().method() === "PUT",
		);
		await proxy.getByRole("button", { name: "保存代理安全设置" }).click();
		assert.equal((await psaved).status(), 200);
		const policy = await (
			await ctx.request.get("/api/settings/proxy-security", { headers })
		).json();
		assert.equal(policy.task_requests_per_minute, 13);
		assert.equal(policy.passthrough_mode, "block");
		await proxy
			.getByLabel("HTTPS 无法解析时", { exact: true })
			.selectOption("allow");
		await proxy.getByRole("note").waitFor();
		const modeSaved = page.waitForResponse(
			(r) =>
				r.url().endsWith("/api/settings/proxy-security") &&
				r.request().method() === "PUT",
		);
		await proxy.getByRole("button", { name: "保存代理安全设置" }).click();
		assert.equal((await modeSaved).status(), 200);
		await page.reload();
		await page.waitForFunction(
			() =>
				document.querySelector("select")?.value === "allow" ||
				[...document.querySelectorAll("select")].some(
					(s) => s.value === "allow",
				),
		);
		assert.equal(
			await proxy.getByLabel("HTTPS 无法解析时", { exact: true }).inputValue(),
			"allow",
		);
		const invalidMode = await ctx.request.put("/api/settings/proxy-security", {
			headers,
			data: { ...policy, passthrough_mode: "invalid" },
		});
		assert.equal(invalidMode.status(), 400);
		assert.equal(
			(
				await (
					await ctx.request.get("/api/settings/proxy-security", { headers })
				).json()
			).passthrough_mode,
			"allow",
		);
		const restored = await ctx.request.put("/api/settings/proxy-security", {
			headers,
			data: policy,
		});
		assert.equal(restored.status(), 200);
		// Invalid values cannot replace a valid saved policy.
		const invalid = await ctx.request.put("/api/settings/proxy-security", {
			headers,
			data: { ...policy, max_body_kib: 0 },
		});
		assert.equal(invalid.status(), 400);
		await page.reload();
		await proxy.getByLabel("每任务每分钟请求数", { exact: true }).waitFor();
		await page.waitForFunction(() =>
			[...document.querySelectorAll("input")].some((x) => x.value === "13"),
		);
		await page.screenshot({
			path: "/tmp/artex-behavior-settings.png",
			fullPage: true,
		});
		await page.goto("/function/assets");
		await page.getByRole("tab", { name: "服务" }).click();
		const detail = page
			.locator("details")
			.filter({
				has: page
					.locator("summary")
					.getByText("HTTP 行为验证与历史", { exact: true }),
			})
			.first();
		await detail.locator("summary").first().click();
		assert.equal(
			await detail.getByRole("button", { name: "发起行为验证" }).isEnabled(),
			false,
		);
		await detail.getByRole("checkbox").check();
		const run = page.waitForResponse(
			(r) =>
				r.url().includes("/honeypot-behavior") &&
				r.request().method() === "POST",
		);
		await detail.getByRole("button", { name: "发起行为验证" }).click();
		const resp = await run;
		assert.equal(resp.status(), 200);
		const record = await resp.json();
		assert.equal(record.result.outcome, "suspected");
		assert.equal(record.result.observations.length, 4);
		await detail
			.getByText(/疑似蜜罐线索/)
			.first()
			.waitFor();
		const duplicate = await ctx.request.post(
			"/api/assets/" + process.env.ASSET_ID + "/honeypot-behavior",
			{ headers, data: { confirm: true, origin: "http://target:8080" } },
		);
		assert.equal(duplicate.status(), 429);
		const history = await (
			await ctx.request.get(
				"/api/assets/" + process.env.ASSET_ID + "/honeypot-behavior",
				{ headers },
			)
		).json();
		assert.equal(history.length, 1);
		assert.equal(history[0].status, "complete");
		const metrics = await (
			await ctx.request.get("http://target:8080/metrics")
		).json();
		assert.equal(metrics.requests, 4);
		assert.equal(metrics.credential_seen, false);
		assert.equal(metrics.unexpected_host, false);
		const upstreamMetrics = await (await ctx.request.get("http://upstream:8081/metrics")).json();
		assert.equal(upstreamMetrics.connects, 4, "all behavior requests must use pinned upstream tunnels");
		const upstreamCleared = await ctx.request.put("/api/settings", {
			headers, data: { global_proxy: "" },
		});
		assert.equal(upstreamCleared.status(), 200);
		const statistics = await (
			await ctx.request.get("/api/proxy-security/stats", { headers })
		).json();
		assert.equal(statistics.stats.allowed, 4);
		await page.screenshot({
			path: "/tmp/artex-behavior-assets.png",
			fullPage: true,
		});
		// Capture OFF must retain the proxy guard while storing no new exchanges.
		const trafficState = async () =>
			(await ctx.request.get("/api/traffic", { headers })).json();
		assert.equal((await trafficState()).enabled, false);
		assert.equal((await trafficState()).count, 0);
		assert.equal(await throughProxy("?phase=off"), 200);
		assert.equal(
			await throughProxy("?phase=blocked", {
				"X-Test": "-----BEGIN PRIVATE KEY-----",
			}),
			403,
		);
		assert.equal((await trafficState()).count, 0);
		await page.goto("/system/settings");
		await page
			.getByText("已关闭 · 不保存流量，代理防护保留", { exact: true })
			.waitFor();
		const toggle = async () => {
			const saved = page.waitForResponse(
				(r) =>
					r.url().endsWith("/api/settings") && r.request().method() === "PUT",
			);
			await page.locator("#traffic-capture").click();
			assert.equal((await saved).status(), 200);
		};
		await toggle();
		assert.equal(await throughProxy("?phase=on"), 200);
		const recorded = (await trafficState()).count;
		assert.ok(recorded > 0);
		await toggle();
		assert.equal(await throughProxy("?phase=off-again"), 200);
		assert.equal((await trafficState()).count, recorded);
		const limited = await ctx.request.put("/api/settings/proxy-security", {
			headers,
			data: { ...policy, unattributed_requests_per_minute: 1 },
		});
		assert.equal(limited.status(), 200);
		assert.equal(await throughProxy("?phase=budget"), 429);
		assert.equal((await trafficState()).count, recorded);
		await page.reload();
		await page
			.getByText("安全代理：已配置，独立于流量捕获", { exact: true })
			.waitFor();
		const finalStats = await (
			await ctx.request.get("/api/proxy-security/stats", { headers })
		).json();
		assert.equal(finalStats.proxy_configured, true);
		assert.equal(finalStats.capture_enabled, false);
		assert.equal(finalStats.stats.blocked.platform_credential, 1);
		assert.equal(finalStats.stats.blocked.task_budget, 1);
		const finalMetrics = await (
			await ctx.request.get("http://target:8080/metrics")
		).json();
		assert.equal(finalMetrics.requests, 7);
		await page.screenshot({
			path: "/tmp/artex-behavior-settings.png",
			fullPage: true,
		});
		assert.deepEqual(errors, []);
		console.log(
			JSON.stringify({
				settings_saved: true,
				policy_reloaded: true,
				behavior: record.result.outcome,
				requests: metrics.requests,
				credentials_sent: metrics.credential_seen,
				upstream_connects: upstreamMetrics.connects,
				original_host_preserved: !metrics.unexpected_host,
				cooldown: duplicate.status(),
				passthrough_policy_saved: true,
				capture_off_protected: true,
				capture_toggle_preserved_history: true,
				page_errors: errors,
			}),
		);
	} catch (error) {
		if (page) {
			console.error("Browser location:", page.url(), "Page errors:", errors);
			await page
				.screenshot({ path: "/tmp/artex-behavior-failure.png", fullPage: true })
				.catch(() => {});
		}
		throw error;
	} finally {
		await browser.close();
	}
})().catch((e) => {
	console.error(e);
	process.exit(1);
});
