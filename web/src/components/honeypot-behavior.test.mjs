import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import test from "node:test";
import vm from "node:vm";
import React from "react";
import { renderToStaticMarkup } from "react-dom/server";
import ts from "typescript";

const require = createRequire(import.meta.url);
const code = ts.transpileModule(
  readFileSync(new URL("./honeypot-behavior.tsx", import.meta.url), "utf8"),
  { compilerOptions: { module: ts.ModuleKind.CommonJS, jsx: ts.JsxEmit.ReactJSX } },
).outputText;

// Render the real component with a loaded history, without a browser or API.
function renderHistory(result, stale = false) {
  const records = [{ id: 1, created_at: "2026-11-07T00:00:00Z", status: "complete", result, stale }];
  const exports = {};
  vm.runInNewContext(code, {
    exports,
    URL,
    require(name) {
      if (name === "react") return {
        ...React,
        useState: initial => React.useState(Array.isArray(initial) ? records : initial),
      };
      if (name === "@/lib/api") return { http: () => { throw new Error("unexpected API call"); } };
      if (name === "@/components/ui/button") return {
        Button: ({ children, disabled }) => React.createElement("button", { disabled }, children),
      };
      return require(name);
    },
  });
  return renderToStaticMarkup(React.createElement(exports.HoneypotBehavior, {
    asset: { id: 1, type: "service", url: "https://example.test/" },
  }));
}

test("content risk stays visible with each independent honeypot outcome", () => {
  for (const [outcome, label] of Object.entries({
    no_signal: "未发现行为线索", needs_review: "蜜罐线索待人工核对",
    suspected: "疑似蜜罐线索", inconclusive: "无法确认",
  })) {
    const html = renderHistory({ outcome, content_warnings: ["<script>example</script>"] });
    assert.ok(html.includes(label));
    assert.match(html, /<summary>[^<]*有内容风险提示<\/summary>/);
    assert.ok(html.includes('role="note"'));
    assert.ok(html.includes("内容风险提示（独立于蜜罐结论）"));
    assert.ok(html.includes("&lt;script&gt;example&lt;/script&gt;"));
    assert.ok(!html.includes("<script>"));
  }
});

test("old history keeps its original signals and stale marker without inventing warnings", () => {
  const html = renderHistory({ outcome: "needs_review", signals: ["旧版内容线索"] }, true);
  assert.ok(html.includes("旧版内容线索"));
  assert.ok(html.includes("资产或规则已变化"));
  assert.ok(!html.includes('role="note"'));
  assert.ok(!renderHistory({ outcome: "no_signal", content_warnings: [] }).includes("有内容风险提示"));
});
