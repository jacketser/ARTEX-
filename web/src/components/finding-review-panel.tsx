"use client";

import * as React from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { http } from "@/lib/api";

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
const empty: Review = { fingerprint: "", verdict: "inconclusive", sources: "", reproduction: "", counter_evidence: "", limitations: "" };
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
  const endpoint = `/exploration/findings/${encodeURIComponent(findingId)}/review`;
  const load = React.useCallback(async (signal?: AbortSignal) => {
    try {
      const data = await http<ReviewState>(endpoint, { signal });
      if (signal?.aborted) return;
      setState(data);
      setDraft({ ...(data.review ?? empty), fingerprint: data.fingerprint });
      setError("");
    } catch (e) { if (!signal?.aborted) setError((e as Error).message); }
  }, [endpoint]);
  React.useEffect(() => {
    const controller = new AbortController();
    void load(controller.signal);
    return () => controller.abort();
  }, [load]);
  async function save() {
    if (readOnly || !state) return;
    setSaving(true);
    try {
      const data = await http<ReviewState>(endpoint, { method: "PUT", body: JSON.stringify(draft) });
      setState(data);
      setDraft({ ...(data.review ?? draft), fingerprint: data.fingerprint });
      setError("");
    } catch (e) { setError((e as Error).message); }
    finally { setSaving(false); }
  }
  return (
    <Card>
      <CardHeader>
        <CardTitle>证据与反证复核</CardTitle>
        <CardDescription>人工核对已有证据，单独保存复核结论。需要补充验证时，可使用下方的漏洞复测。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {error && <p role="alert" className="text-sm text-destructive">{error}</p>}
        {state?.warnings.map((warning) => <p key={warning} className="text-sm text-muted-foreground">{warning}</p>)}
        {state?.stale && <p className="text-sm font-medium">此前复核已过期，请核对新证据后重新保存。</p>}
        {state && (
          <fieldset disabled={readOnly || saving} className="space-y-3">
            {fields.map(([key, label, placeholder]) => (
              <label key={key} className="block space-y-1 text-sm">
                <span>{label}</span>
                <Textarea value={draft[key]} placeholder={placeholder} maxLength={16000}
                  onChange={(e) => setDraft((value) => ({ ...value, [key]: e.target.value }))} />
              </label>
            ))}
            <label className="flex items-center gap-3 text-sm">
              <span>复核结论</span>
              <select className="rounded border bg-background p-2" value={draft.verdict}
                onChange={(e) => setDraft((value) => ({ ...value, verdict: e.target.value as Review["verdict"] }))}>
                <option value="inconclusive">证据不足，无法确认</option>
                <option value="supported">现有证据支持结论</option>
                <option value="refuted">现有证据反驳结论</option>
              </select>
            </label>
            {!readOnly && <Button onClick={() => void save()} disabled={saving}>{saving ? "保存中…" : "保存复核"}</Button>}
            {state.review?.updated_at && <p className="text-xs text-muted-foreground">上次保存：{new Date(state.review.updated_at).toLocaleString("zh-CN")}</p>}
          </fieldset>
        )}
        <Button variant="outline" size="sm" disabled={saving} onClick={() => void load()}>重新加载复核</Button>
      </CardContent>
    </Card>
  );
}
