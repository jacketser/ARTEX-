"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { api, http } from "@/lib/api";
import type { AutoReviewResult } from "@/lib/types";
import { ReviewHistory } from "@/components/review-history";
import { TrafficEvidenceViewer } from "@/components/traffic-evidence-viewer";
import { FindingRetestDialog } from "@/components/finding-retest-dialog";

type Review = {
  fingerprint: string;
  verdict: "supported" | "refuted" | "inconclusive";
  sources: string;
  reproduction: string;
  counter_evidence: string;
  limitations: string;
  updated_at?: string;
};
type ReviewState = { fingerprint: string; review: Review | null; stale: boolean; warnings: string[] };

const empty: Review = {
  fingerprint: "",
  verdict: "inconclusive",
  sources: "",
  reproduction: "",
  counter_evidence: "",
  limitations: "",
};
const fields = [
  ["sources", "证据来源", "记录真实流量编号、日志位置或原始输出，并说明它支持哪项结论。"],
  ["reproduction", "复现条件与实际观察", "记录环境、前置条件、预期与实际结果；将观察事实与推断分开。"],
  ["counter_evidence", "反证与替代解释", "核对正常对照、权限差异、缓存或环境差异等解释，注明尚未排除的可能。"],
  ["limitations", "限制与缺失证据", "列出未验证项、证据缺口及下一步需要人工确认的事项。"],
] as const;

export function FindingReviewPanel({ findingId, readOnly = false }: { findingId: string; readOnly?: boolean }) {
  const [state, setState] = React.useState<ReviewState | null>(null);
  const [draft, setDraft] = React.useState<Review>(empty);
  const [error, setError] = React.useState("");
  const [saving, setSaving] = React.useState(false);
  const [auto, setAuto] = React.useState<AutoReviewResult | null>(null);
  const [autoBusy, setAutoBusy] = React.useState(false);
  const [autoError, setAutoError] = React.useState("");
  const [historyRevision, setHistoryRevision] = React.useState(0);
  const [preview, setPreview] = React.useState<string | null>(null);
  const [retest, setRetest] = React.useState(false);
  const requestVersion = React.useRef(0);
  const endpoint = `/exploration/findings/${encodeURIComponent(findingId)}/review`;
  const load = React.useCallback(
    async (signal?: AbortSignal) => {
      const version = ++requestVersion.current;
      try {
        const [manual, automatic] = await Promise.allSettled([
          http<ReviewState>(endpoint, { signal }),
          api.autoReviewFinding(findingId, signal),
        ]);
        if (signal?.aborted || version !== requestVersion.current) return;
        if (manual.status === "rejected") throw manual.reason;
        const data = manual.value;
        setAuto(
          automatic.status === "fulfilled" && automatic.value.fingerprint === data.fingerprint
            ? automatic.value.review
            : null,
        );
        setAutoError(
          automatic.status === "rejected"
            ? "自动审阅暂时不可用，仍可完成人工复核。"
            : automatic.value.fingerprint !== data.fingerprint
              ? "证据已变化，请重新加载复核。"
              : "",
        );
        setState(data);
        setDraft({ ...(data.review ?? empty), fingerprint: data.fingerprint });
        setError("");
      } catch (e) {
        if (!signal?.aborted && version === requestVersion.current) setError((e as Error).message);
      }
    },
    [endpoint, findingId],
  );
  React.useEffect(() => {
    const controller = new AbortController();
    setState(null);
    setAuto(null);
    setAutoError("");
    setAutoBusy(false);
    setSaving(false);
    void load(controller.signal);
    return () => {
      controller.abort();
      requestVersion.current++;
    };
  }, [load]);
  async function save() {
    if (readOnly || !state) return;
    const version = ++requestVersion.current;
    setSaving(true);
    try {
      const data = await http<ReviewState>(endpoint, { method: "PUT", body: JSON.stringify(draft) });
      if (version !== requestVersion.current) return;
      setState(data);
      setDraft({ ...(data.review ?? draft), fingerprint: data.fingerprint });
      setAuto(null);
      setHistoryRevision((v) => v + 1);
      await runAutoReview(data.fingerprint);
      setError("");
    } catch (e) {
      if (version === requestVersion.current) setError((e as Error).message);
    } finally {
      if (version === requestVersion.current) setSaving(false);
    }
  }
  async function runAutoReview(expected = state?.fingerprint) {
    const version = requestVersion.current;
    setAutoBusy(true);
    setAuto(null);
    setAutoError("");
    try {
      const result = await api.autoReviewFinding(findingId, undefined, !readOnly);
      if (version !== requestVersion.current) return;
      if (expected && result.fingerprint !== expected) {
        setAutoError("证据已变化，请重新加载复核。");
        return;
      }
      setAuto(result.review);
      setHistoryRevision((v) => v + 1);
    } catch (e) {
      if (version === requestVersion.current) setAutoError((e as Error).message);
    } finally {
      if (version === requestVersion.current) setAutoBusy(false);
    }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>证据与反证复核</CardTitle>
        <CardDescription>
          自动检查当前已保存证据、对照与复测记录，并给出分类反证建议。人工复核单独保存，不会自动更改漏洞处置状态。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && (
          <p role="alert" className="text-sm text-destructive">
            {error}
          </p>
        )}
        {autoError && (
          <p role="alert" className="text-sm text-destructive">
            {autoError}
          </p>
        )}
        {state?.warnings.map((warning) => (
          <p key={warning} className="text-sm text-muted-foreground">
            {warning}
          </p>
        ))}
        {state?.stale && <p className="text-sm font-medium">此前复核已过期，请核对新证据后重新保存。</p>}
        {
          <Button variant="outline" size="sm" disabled={autoBusy || saving} onClick={() => void runAutoReview()}>
            {autoBusy ? "审阅中…" : "自动审阅现有证据"}
          </Button>
        }
        {auto && (
          <div className="space-y-2 rounded border p-3 text-sm" role="status">
            <p className="font-medium">
              自动反证审阅：
              {auto.verdict === "supported"
                ? "沿用人工支持结论"
                : auto.verdict === "refuted"
                  ? "沿用人工反驳结论"
                  : "需人工确认"}
            </p>
            <p>{auto.basis}</p>
            {auto.checks.map((check) => (
              <p key={check.key} className="text-muted-foreground">
                {check.passed ? "已记录" : "待补充"} · {check.label}：{check.details}
              </p>
            ))}
            {auto.missing.length > 0 && <p>缺少或需核对：{auto.missing.join("、")}</p>}
            <p className="pt-2 font-medium">建议核对的反证</p>
            <ul className="list-disc space-y-1 pl-5">
              {auto.suggestions.map((item) => (
                <li key={item}>{item}</li>
              ))}
            </ul>
            {auto.warnings.map((warning) => (
              <p key={warning} className="text-xs text-muted-foreground">
                {warning}
              </p>
            ))}
            {auto.comparisons?.map((c) => (
              <div key={`${c.baseline_id}-${c.proof_id}`} className="space-y-1 border-t pt-2">
                <p className="font-medium">已保存流量对比</p>
                <Button size="sm" variant="link" onClick={() => setPreview(c.baseline_id)}>
                  正常对照 #{c.baseline_id}
                </Button>
                <Button size="sm" variant="link" onClick={() => setPreview(c.proof_id)}>
                  证明流量 #{c.proof_id}
                </Button>
                {c.differences.map((x) => (
                  <p key={x}>{x}</p>
                ))}
                {c.bodies.map((b) => (
                  <p key={b.side}>
                    {b.side === "request" ? "请求" : "响应"}正文：{b.baseline_length} → {b.proof_length} 字节；
                    {b.details}
                    {b.first_difference !== undefined ? `（偏移 ${b.first_difference}）` : ""}
                  </p>
                ))}
                <p className="text-xs text-muted-foreground">{c.limitation}</p>
              </div>
            ))}
            {!readOnly && (
              <Button size="sm" variant="outline" onClick={() => setRetest(true)}>
                将缺失项带入复测
              </Button>
            )}
          </div>
        )}
        {state && (
          <fieldset disabled={readOnly || saving || autoBusy} className="space-y-3">
            {fields.map(([key, label, placeholder]) => (
              <label key={key} className="block space-y-1 text-sm">
                <span>{label}</span>
                <Textarea
                  value={draft[key]}
                  placeholder={placeholder}
                  maxLength={16000}
                  onChange={(e) => setDraft((value) => ({ ...value, [key]: e.target.value }))}
                />
              </label>
            ))}
            <label className="flex items-center gap-3 text-sm">
              <span>复核结论</span>
              <select
                className="rounded border bg-background p-2"
                value={draft.verdict}
                onChange={(e) => setDraft((value) => ({ ...value, verdict: e.target.value as Review["verdict"] }))}
              >
                <option value="inconclusive">证据不足，无法确认</option>
                <option value="supported">现有证据支持结论</option>
                <option value="refuted">现有证据反驳结论</option>
              </select>
            </label>
            {!readOnly && (
              <Button onClick={() => void save()} disabled={saving}>
                {saving ? "保存中…" : "保存复核"}
              </Button>
            )}
            {state.review?.updated_at && (
              <p className="text-xs text-muted-foreground">
                上次保存：{new Date(state.review.updated_at).toLocaleString("zh-CN")}
              </p>
            )}
          </fieldset>
        )}
        <Button variant="outline" size="sm" disabled={saving || autoBusy} onClick={() => void load()}>
          重新加载复核
        </Button>
        <ReviewHistory findingId={findingId} fingerprint={state?.fingerprint} revision={historyRevision} />
        {preview && (
          <TrafficEvidenceViewer findingId={findingId} bindingId={preview} onClose={() => setPreview(null)} />
        )}
        {retest && auto && (
          <FindingRetestDialog
            findingId={findingId}
            initialNotes={`请核对以下证据缺口与替代解释，以下为规则建议，不是已确认事实。\n待补充：${auto.missing.join("、")}\n${auto.suggestions.join("\n")}`}
            onClose={() => setRetest(false)}
            onStarted={() => window.dispatchEvent(new Event("finding-retest-started"))}
          />
        )}
      </CardContent>
    </Card>
  );
}
