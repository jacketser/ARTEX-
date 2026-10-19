"use client";
import * as React from "react";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import type { Asset, HoneypotResult } from "@/lib/types";

export function HoneypotAssessment({ asset }: { asset: Asset }) {
  const result = asset.honeypot;
  if (!result) return <span className="text-xs text-muted-foreground">尚未评估</span>;
  const confidence = { none: "无", low: "低", medium: "中", high: "高" }[result.confidence];
  return (
    <details className="max-w-64 text-xs">
      <summary className="cursor-pointer" aria-label={`资产 ${asset.id} 蜜罐识别详情`}>
        <Badge variant="outline" className={result.matched ? "text-amber-600" : "text-muted-foreground"}>{result.matched ? `疑似蜜罐 · ${confidence}置信` : "未发现显式签名"}</Badge>
      </summary>
      <div className="mt-2 space-y-1 whitespace-normal">
        <p>上次保存的评估；元数据更新后请重新识别。</p>
        <p>规则评分：{result.score}/100（不是概率）</p>
        {result.provider && <p>名称标记：{result.provider}</p>}
        {result.evidence.map((item) => <p key={item}>{item}</p>)}
        <p className="text-muted-foreground">{result.limitations}</p>
      </div>
    </details>
  );
}

export function HoneypotScanButton({ assets, onResults }: { assets: Asset[]; onResults: (items: { id: number; result: HoneypotResult }[]) => void }) {
  const [busy, setBusy] = React.useState(false);
  async function assess() {
    setBusy(true);
    try { const out = await api.assessHoneypots(assets.map((a) => a.id)); onResults(out.results); toast.success(`已保存 ${out.count} 项元数据识别结果，未发起探测`); }
    catch (e) { toast.error((e as Error).message); }
    finally { setBusy(false); }
  }
  return <Button variant="outline" size="sm" disabled={busy || assets.length === 0} onClick={() => void assess()}>{busy ? "保存中…" : "保存本页蜜罐识别"}</Button>;
}
