"use client";
import * as React from "react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import type { Asset } from "@/lib/types";
type Observation = {
    method: string;
    path: string;
    status: number;
    body_sha256?: string;
    bytes: number;
    truncated: boolean;
    duration_ms: number;
    error?: string;
};
type Result = {
    outcome?: string;
    confidence?: string;
    signals?: string[];
    observations?: Observation[];
    limitations?: string;
};
type RecordItem = {
    id: number;
    origin: string;
    status: string;
    created_at: string;
    finished_at?: string;
    result: Result;
    stale: boolean;
};
const outcomes: Record<string, string> = { no_signal: "未发现行为线索", needs_review: "行为差异待人工核对", suspected: "疑似蜜罐线索", inconclusive: "无法确认" };
const statuses: Record<string, string> = { running: "探测中", complete: "已结束", blocked: "被安全检查阻止", interrupted: "已中断" };
const probeErrors: Record<string, string> = { security_budget_or_policy: "安全策略或请求限额阻止", network_tls_or_timeout: "网络、证书或超时失败", body_read: "正文读取失败", encoded_body_not_analyzed: "压缩正文未分析" };
export function HoneypotBehavior({ asset }: {
    asset: Asset;
}) {
    const [records, setRecords] = React.useState<RecordItem[]>([]), [busy, setBusy] = React.useState(false), [loading, setLoading] = React.useState(false), [error, setError] = React.useState(""), [confirm, setConfirm] = React.useState(false), [more, setMore] = React.useState(false);
    const controller = React.useRef<AbortController | null>(null);
    React.useEffect(() => () => controller.current?.abort(), []);
    let origin = "";
    try {
        const u = new URL(asset.url ?? "");
        u.hostname = u.hostname.toLowerCase().replace(/\.$/, "");
        if (["http:", "https:"].includes(u.protocol) && !u.username && !u.password)
            origin = u.origin;
    }
    catch { }
    async function load(before = 0) { setLoading(true); try {
        const rows = await http<RecordItem[]>("/assets/" + asset.id + "/honeypot-behavior" + (before ? "?before=" + before : ""));
        setRecords(prev => before ? [...prev, ...rows] : rows);
        setMore(rows.length === 10);
    }
    catch (e) {
        setError((e as Error).message);
    }
    finally {
        setLoading(false);
    } }
    async function run() {
        setBusy(true);
        setError("");
        controller.current = new AbortController();
        try {
            await http("/assets/" + asset.id + "/honeypot-behavior", { method: "POST", body: JSON.stringify({ confirm, origin }), signal: controller.current.signal });
            setConfirm(false);
            await load();
        }
        catch (e) {
            if (!controller.current.signal.aborted)
                setError((e as Error).message);
        }
        finally {
            setBusy(false);
        }
    }
    if (asset.type !== "service" || !origin)
        return null;
    return <details className="mt-2 max-w-sm text-xs" onToggle={e => { if (e.currentTarget.open && records.length === 0 && !loading)
        void load(); }}>
  <summary className="cursor-pointer">HTTP 行为验证与历史</summary>
  <div className="mt-2 space-y-2 whitespace-normal">
   <p className="break-all">验证来源：{origin}</p>
   <p>人工发起最多四次请求：主页两次 GET、一次 HEAD、随机不存在路径一次 GET。不携带凭据、不跟随跳转，每服务间隔五分钟。</p>
   <p>先在系统设置中启用并添加精确授权来源。仅保存状态、摘要哈希及线索，不保存响应正文；结果不自动改变任务执行。</p>
   <label className="flex items-start gap-2"><input type="checkbox" checked={confirm} disabled={busy} onChange={e => setConfirm(e.target.checked)}/><span>我确认有权向上述服务发送这些诊断请求</span></label>
   <Button size="sm" variant="outline" disabled={busy || !confirm} onClick={() => void run()}>{busy ? "验证中（最多 20 秒）…" : "发起行为验证"}</Button>
   <Button size="sm" variant="ghost" disabled={loading || busy} onClick={() => void load()}>刷新历史</Button>
   {error && <p role="alert" className="text-destructive">{error}</p>}
   {records.map(rec => <details key={rec.id} className="border-t pt-2"><summary>{new Date(rec.created_at).toLocaleString("zh-CN")} · {statuses[rec.status] ?? rec.status} · {outcomes[rec.result.outcome ?? ""] ?? "尚无结论"}{rec.stale ? "（资产或规则已变化）" : ""}</summary>
    {rec.result.signals?.map((x, i) => <p key={i} className="mt-1">{x}</p>)}
    {rec.result.observations?.map((o, i) => <p key={i} className="mt-1 break-all">{o.method} {o.path} · HTTP {o.status || "无响应"} · {o.duration_ms} ms · {o.bytes} 字节{o.truncated ? "（截断，不作完整正文比较）" : ""}{o.error ? " · " + (probeErrors[o.error] ?? o.error) : ""}{o.body_sha256 ? " · SHA-256 " + o.body_sha256 : ""}</p>)}
    <p className="mt-2 text-muted-foreground">{rec.result.limitations}</p>
   </details>)}
   {more && <Button size="sm" disabled={loading} onClick={() => void load(records.at(-1)?.id)}>加载更早记录</Button>}
  </div>
 </details>;
}
