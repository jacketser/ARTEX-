const { chromium } = require("/usr/local/lib/node_modules/playwright");
const assert = require("node:assert/strict");
const fs = require("node:fs/promises");

(async () => {
  const failedSource = process.env.EXPORT_FAILURE === "1";
  const phase = failedSource ? "failure" : "normal";
  const output = "/tmp/artex-export";
  await fs.mkdir(output, { recursive: true });
  const browser = await chromium.launch({ headless: true, args: ["--no-sandbox"] });
  const errors = [], checks = [];
  let page;
  try {
    const ctx = await browser.newContext({ baseURL: "http://127.0.0.1:8787", viewport: { width: 1440, height: 1000 } });
    const status = await (await ctx.request.get("/api/auth/status")).json();
    assert.equal(status.initialized, failedSource);
    const login = await ctx.request.post(failedSource ? "/api/auth/login" : "/api/auth/init", {
      data: { username: "ARTEX", password: "isolated-share-export-password" },
    });
    assert.equal(login.status(), 200);
    const { token } = await login.json();
    const health = await (await ctx.request.get("/api/health")).json();
    assert.equal(health.version, process.env.EXPORT_EXPECTED_VERSION || "dev-806bc74");
    await ctx.addInitScript(t => localStorage.setItem("artex_token", t), token);
    page = await ctx.newPage();
    page.on("pageerror", e => errors.push(e.message));
    let downloadCount = 0;
    page.on("download", () => downloadCount++);
    await page.goto("/function/findings");
    await page.getByRole("tab", { name: "全部发现", exact: true }).click();
    await page.getByRole("link", { name: /^EXPORT-ALPHA/ }).waitFor();
    const dialog = page.getByRole("dialog");
    const isExport = response => new URL(response.url()).pathname === "/api/exploration/findings/export";
    async function open(fmt, scope) {
      await page.getByRole("button", { name: "导出", exact: true }).click();
      await dialog.locator("#export-format-" + fmt).click();
      if (scope) await dialog.locator("#export-scope-" + scope).click();
      const note = await dialog.getByRole("note").innerText();
      assert.ok(note.includes(fmt === "md-single" || fmt === "csv" ? "脱敏副本不能替代原始证据" : "尚未增加统一导出脱敏"));
    }
    async function download(fmt, scope, name) {
      await open(fmt, scope);
      const [response, file] = await Promise.all([
        page.waitForResponse(isExport), page.waitForEvent("download"),
        dialog.getByRole("button", { name: "导出", exact: true }).click(),
      ]);
      assert.equal(response.status(), 200);
      assert.equal(new URL(response.url()).searchParams.get("scope"), scope);
      const headers = response.headers();
      if (fmt !== "json") {
        assert.equal(headers["cache-control"], "no-store");
        assert.equal(headers["x-artex-export"], "sanitized-copy; not-original-evidence");
        assert.match(file.suggestedFilename(), /^findings-sanitized-.*\.(md|csv)$/);
      } else {
        assert.equal(headers["x-artex-export"], undefined);
        assert.ok(!file.suggestedFilename().includes("sanitized"));
      }
      assert.ok(headers["content-disposition"].includes(file.suggestedFilename()));
      await file.saveAs(output + "/" + name);
      assert.equal(await file.failure(), null);
      await dialog.waitFor({ state: "hidden" });
      checks.push({ format: fmt, scope, filename: file.suggestedFilename(), status: response.status() });
    }
    if (failedSource) {
      for (const fmt of ["md-single", "csv"]) {
        await open(fmt, "all");
        const [response] = await Promise.all([
          page.waitForResponse(isExport),
          dialog.getByRole("button", { name: "导出", exact: true }).click(),
        ]);
        assert.equal(response.status(), 503);
        assert.equal(response.headers()["content-disposition"], undefined);
        assert.equal(response.headers()["x-artex-export"], undefined);
        const body = await response.text();
        assert.ok(!body.includes("synthetic-export") && !body.includes("llm_profiles") && !body.includes("EXPORT-ALPHA"));
        await page.getByText("导出失败：export: 503", { exact: true }).first().waitFor();
        await page.screenshot({ path: output + "/failure-" + fmt + ".png" });
        // Allow completion of the asynchronous UI error path before asserting no download.
        await page.waitForTimeout(1000);
        assert.equal(downloadCount, 0);
        await dialog.getByRole("button", { name: "取消", exact: true }).click();
        checks.push({ format: fmt, status: response.status(), download_count: downloadCount });
      }
    } else {
      for (const fmt of ["md-zip", "json", "md-single", "csv"]) {
        await open(fmt, "all");
        await page.screenshot({ path: output + "/notice-" + fmt + ".png" });
        await dialog.getByRole("button", { name: "取消", exact: true }).click();
      }
      for (const fmt of ["md-single", "csv"]) await download(fmt, "all", "all." + (fmt === "csv" ? "csv" : "md"));
      await download("json", "all", "original.json");
      const alphaRow = page.locator("tr").filter({ has: page.getByRole("link", { name: /^EXPORT-ALPHA/ }) });
      await alphaRow.getByRole("checkbox", { name: "选择该漏洞" }).click();
      for (const fmt of ["md-single", "csv"]) await download(fmt, "selected", "selected." + (fmt === "csv" ? "csv" : "md"));
      await alphaRow.getByRole("checkbox", { name: "选择该漏洞" }).click();
      await page.getByRole("searchbox", { name: "检索漏洞内容" }).fill("EXPORT-ALPHA");
      await page.getByRole("link", { name: "EXPORT-BETA", exact: true }).waitFor({ state: "hidden" });
      for (const fmt of ["md-single", "csv"]) await download(fmt, "filtered", "filtered." + (fmt === "csv" ? "csv" : "md"));
      assert.equal(downloadCount, 7);
    }
    assert.deepEqual(errors, []);
    const result = { passed: true, phase, version: health.version, checks, page_errors: errors, download_count: downloadCount };
    await fs.writeFile(output + "/" + phase + ".json", JSON.stringify(result, null, 2));
    console.log(JSON.stringify(result, null, 2));
  } catch (error) {
    if (page) await page.screenshot({ path: output + "/error-" + phase + ".png" }).catch(() => {});
    throw error;
  } finally {
    await browser.close();
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
