"use client";
import * as React from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api, http } from "@/lib/api";
import { Textarea } from "@/components/ui/textarea";
import type { Asset, HoneypotResult } from "@/lib/types";

export function HoneypotAssessment({ asset, onChanged }: { asset: Asset; onChanged?: () => void }) {
  const [note, setNote] = React.useState("");
  const [verdict, setVerdict] = React.useState("confirmed");
  const [busy, setBusy] = React.useState(false);
  async function save() {
    if (!asset.honeypot) return;
    setBusy(true);
    try {
      await http(`/assets/${asset.id}/honeypot-review`, {
        method: "PUT",
        body: JSON.stringify({ fingerprint: asset.honeypot.fingerprint, verdict, note }),
      });
      toast.success("人工复核已保存");
      onChanged?.();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const result = asset.honeypot;
  if (!result) return <span className="text-xs text-muted-foreground">尚未评估</span>;
  const confidence = { none: "无", low: "低", medium: "中", high: "高" }[result.confidence];
  const manual = asset.honeypot_review;
  const current = manual && !manual.stale && manual.fingerprint === result.fingerprint && !result.stale;
  return (
    <details className="max-w-64 text-xs">
      <summary className="cursor-pointer" aria-label={`资产 ${asset.id} 蜜罐识别详情`}>
        <Badge variant="outline" className={result.matched ? "text-amber-600" : "text-muted-foreground"}>
          {result.stale
            ? "评估已过期 · 等待重评"
            : current && manual.verdict === "confirmed"
              ? "人工确认蜜罐"
              : current && manual.verdict === "excluded"
                ? "人工排除蜜罐"
                : result.matched
                  ? `疑似蜜罐 · ${confidence}置信`
                  : "未发现显式签名"}
        </Badge>
      </summary>
      <div className="mt-2 space-y-1 whitespace-normal">
        <p>
          {result.stale ? "元数据或规则已变化，后台将重新评估。" : "元数据或规则变化后会自动重评；人工结论需重新确认。"}
        </p>
        {result.assessed_at && <p>评估时间：{new Date(result.assessed_at * 1000).toLocaleString("zh-CN")}</p>}
        {result.sources?.map((source) => (
          <p key={source} className="text-muted-foreground">
            依据：{source}
          </p>
        ))}
        <p>规则评分：{result.score}/100（不是概率）</p>
        {result.provider && <p>名称标记：{result.provider}</p>}
        {result.evidence.map((item) => (
          <p key={item}>{item}</p>
        ))}
        <p className="text-muted-foreground">{result.limitations}</p>
        {manual && (
          <p>
            人工记录{current ? "" : "（已过期）"}：{manual.note}
          </p>
        )}
        <fieldset disabled={busy || result.stale} className="space-y-2 border-t pt-2">
          <label className="block">
            人工结论
            <select
              aria-label={`资产 ${asset.id} 人工蜜罐结论`}
              className="ml-2 rounded border bg-background"
              value={verdict}
              onChange={(e) => setVerdict(e.target.value)}
            >
              <option value="confirmed">确认</option>
              <option value="excluded">排除</option>
              <option value="unreviewed">撤销人工结论</option>
            </select>
          </label>
          <Textarea
            aria-label={`资产 ${asset.id} 蜜罐复核依据`}
            placeholder="填写确认或排除依据"
            maxLength={1000}
            value={note}
            onChange={(e) => setNote(e.target.value)}
          />
          <Button
            size="sm"
            variant="outline"
            disabled={verdict !== "unreviewed" && !note.trim()}
            onClick={() => void save()}
          >
            保存人工结论
          </Button>
        </fieldset>
      </div>
    </details>
  );
}

export function HoneypotFilter({ onPick }: { onPick: (value: string) => void }) {
  return (
    <select
      aria-label="蜜罐状态快捷筛选"
      className="mr-2 rounded border bg-background p-1 text-xs"
      defaultValue=""
      onChange={(e) => onPick(e.target.value)}
    >
      <option value="">全部（清除搜索）</option>
      <option value="suspected">疑似蜜罐</option>
      <option value="confirmed">人工确认</option>
      <option value="excluded">人工排除</option>
      <option value="stale">评估过期</option>
      <option value="unassessed">尚未评估</option>
      <option value="none">未发现签名</option>
    </select>
  );
}

export function HoneypotScanButton({
  assets,
  onResults,
}: {
  assets: Asset[];
  onResults: (items: { id: number; result: HoneypotResult }[]) => void;
}) {
  const [busy, setBusy] = React.useState(false);
  async function assess() {
    setBusy(true);
    try {
      const out = await api.assessHoneypots(assets.map((a) => a.id));
      onResults(out.results);
      toast.success(`已保存 ${out.count} 项元数据识别结果，未发起探测`);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <Button variant="outline" size="sm" disabled={busy || assets.length === 0} onClick={() => void assess()}>
      {busy ? "保存中…" : "保存本页蜜罐识别"}
    </Button>
  );
}
