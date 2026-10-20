"use client";
import * as React from "react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import type { AutoReviewResult } from "@/lib/types";
type Entry = {
  id: number;
  kind: string;
  fingerprint: string;
  created_at: string;
  result: {
    verdict?: string;
    basis?: string;
    sources?: string;
    reproduction?: string;
    counter_evidence?: string;
    limitations?: string;
    missing?: string[];
    suggestions?: string[];
    warnings?: string[];
    checks?: AutoReviewResult["checks"];
    comparisons?: AutoReviewResult["comparisons"];
  };
};
export function ReviewHistory({
  findingId,
  fingerprint,
  revision,
}: {
  findingId: string;
  fingerprint?: string;
  revision: number;
}) {
  const [items, setItems] = React.useState<Entry[]>([]);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [more, setMore] = React.useState(false);
  const sequence = React.useRef(0);
  const load = React.useCallback(
    async (before = 0) => {
      const seq = ++sequence.current;
      setBusy(true);
      try {
        const rows = await http<Entry[]>(
          `/exploration/findings/${encodeURIComponent(findingId)}/review-history?before=${before}`,
        );
        if (seq !== sequence.current) return;
        setItems((prev) => (before ? [...prev, ...rows] : rows));
        setMore(rows.length === 50);
        setError("");
      } catch (e) {
        if (seq === sequence.current) setError((e as Error).message);
      } finally {
        if (seq === sequence.current) setBusy(false);
      }
    },
    [findingId],
  );
  React.useEffect(() => {
    void revision;
    setItems([]);
    void load();
    return () => {
      sequence.current++;
    };
  }, [revision, load]);
  const labels: Record<string, string> = { supported: "支持", refuted: "反驳", inconclusive: "无法确认" };
  return (
    <details className="rounded border p-3 text-sm">
      <summary className="cursor-pointer">审阅历史（{items.length} 条已加载）</summary>
      <p className="my-2 text-xs text-muted-foreground">
        人工保存和手动自动审阅会留存历史；打开页面的只读预览不新增记录。
      </p>
      {error && (
        <p role="alert">
          {error}
          <Button size="sm" variant="outline" onClick={() => void load()}>
            重试
          </Button>
        </p>
      )}
      {items.map((e) => (
        <details key={e.id} className="my-2 border-t pt-2">
          <summary className="cursor-pointer">
            {new Date(e.created_at).toLocaleString("zh-CN")} · {e.kind === "manual" ? "人工复核" : "自动审阅"} ·{" "}
            {labels[e.result.verdict ?? ""] ?? "未确认"}
            {fingerprint && e.fingerprint !== fingerprint ? " · 证据已变化" : ""}
          </summary>
          {[e.result.basis, e.result.sources, e.result.reproduction, e.result.counter_evidence, e.result.limitations]
            .filter(Boolean)
            .map((text, i) => (
              <p key={i} className="whitespace-pre-wrap break-words">
                {text}
              </p>
            ))}
          {e.result.missing?.length ? <p>待补充：{e.result.missing.join("、")}</p> : null}
          {e.result.suggestions?.map((x) => (
            <p key={x}>{x}</p>
          ))}
          {e.result.checks?.map((check) => (
            <p key={check.key}>
              {check.passed ? "已记录" : "待补充"}：{check.label} · {check.details}
            </p>
          ))}
          {e.result.comparisons?.map((c) => (
            <div key={c.baseline_id + "-" + c.proof_id} className="my-2 border-l pl-2">
              <p>
                当时的流量比较：正常对照 #{c.baseline_id} / 证明 #{c.proof_id}
              </p>
              {c.differences.map((x) => (
                <p key={x}>{x}</p>
              ))}
              {c.bodies.map((b) => (
                <p key={b.side}>
                  {b.side === "request" ? "请求" : "响应"}正文：{b.baseline_length} → {b.proof_length} 字节 ·{" "}
                  {b.details}
                  {b.first_difference !== undefined ? "（偏移 " + b.first_difference + "）" : ""}
                </p>
              ))}
            </div>
          ))}
          {e.result.warnings?.map((x) => (
            <p key={x} className="text-xs text-muted-foreground">
              {x}
            </p>
          ))}
        </details>
      ))}
      {more && (
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void load(items.at(-1)?.id)}>
          加载更早审阅
        </Button>
      )}
    </details>
  );
}
