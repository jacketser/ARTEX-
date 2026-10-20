"use client";
import * as React from "react";
import Link from "next/link";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";

type Config = { after_seconds: number; cooldown_seconds: number; observe_seconds: number };
export type RecoveryEvent = {
  id: number;
  task_id: string;
  attempt: number;
  started_at: number;
  observe_until: number;
  finished_at: number;
  status: string;
};
const labels: Record<string, string> = {
  observing: "观察中",
  recovered: "已观察到进展",
  no_progress: "观察期内无有效进展",
  interrupted: "任务状态改变，已结束观察",
};

export function RecoverySettings() {
  const [cfg, setCfg] = React.useState<Config | null>(null);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  React.useEffect(() => {
    const c = new AbortController();
    http<Config>("/settings/auto-recovery", { signal: c.signal })
      .then(setCfg)
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, []);
  async function save() {
    setBusy(true);
    try {
      setCfg(await http<Config>("/settings/auto-recovery", { method: "PUT", body: JSON.stringify(cfg) }));
      setError("");
      toast.success("恢复参数已保存");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="space-y-3 px-6 pb-6">
      {error && (
        <p role="alert" className="text-destructive text-sm">
          {error}
        </p>
      )}
      {cfg && (
        <>
          <div className="grid grid-cols-3 gap-2">
            {(
              [
                ["after_seconds", "停滞阈值"],
                ["cooldown_seconds", "重试冷却"],
                ["observe_seconds", "观察期限"],
              ] as const
            ).map(([key, label]) => (
              <label key={key} className="text-xs">
                {label}（秒）
                <Input
                  type="number"
                  min={30}
                  max={key === "cooldown_seconds" ? 86400 : 3600}
                  value={cfg[key]}
                  disabled={busy}
                  onChange={(e) => setCfg({ ...cfg, [key]: Number(e.target.value) })}
                />
              </label>
            ))}
          </div>
          <p className="text-xs text-muted-foreground">
            冷却不得短于观察期限；连续最多 3 次。观察期限对新唤醒生效，已开始的观察保持原期限。
          </p>
          <Button size="sm" variant="outline" onClick={() => void save()} disabled={busy}>
            {busy ? "保存中…" : "保存恢复参数"}
          </Button>
        </>
      )}
    </div>
  );
}
export function RecoveryHistory({ taskId, recent }: { taskId: string; recent: RecoveryEvent[] }) {
  const [older, setOlder] = React.useState<RecoveryEvent[]>([]);
  const [busy, setBusy] = React.useState(false);
  const [end, setEnd] = React.useState(false);
  const [error, setError] = React.useState("");
  React.useEffect(() => {
    setOlder([]);
    setEnd(false);
  }, [taskId]);
  const items = [...recent, ...older.filter((e) => !recent.some((r) => r.id === e.id))];
  async function more() {
    setBusy(true);
    try {
      const rows = await http<RecoveryEvent[]>(
        `/tasks/${encodeURIComponent(taskId)}/recovery-history?before=${items.at(-1)?.id ?? 0}`,
      );
      setOlder((prev) => [...prev, ...rows]);
      setEnd(rows.length < 50);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return (
    <details className="mt-2">
      <summary className="cursor-pointer">恢复历史（最近 {items.length} 条）</summary>
      <p className="text-xs text-muted-foreground">进展表示 Worker 成功结束或任务完成，不代表唤醒动作是唯一原因。</p>
      {items.map((e) => (
        <p key={e.id} className="mt-1 text-xs">
          {new Date(e.started_at * 1000).toLocaleString("zh-CN")} · 第 {e.attempt} 次 · {labels[e.status] ?? e.status}
        </p>
      ))}
      {error && <p role="alert">{error}</p>}
      {!end && items.length >= 50 && (
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void more()}>
          加载更早记录
        </Button>
      )}
    </details>
  );
}
export function RecoveryAlerts() {
  const [items, setItems] = React.useState<RecoveryEvent[]>([]);
  const [error, setError] = React.useState("");
  React.useEffect(() => {
    const c = new AbortController();
    const load = () =>
      http<RecoveryEvent[]>("/recovery-alerts", { signal: c.signal })
        .then((rows) => {
          setItems(rows);
          setError("");
        })
        .catch((e) => {
          if (!c.signal.aborted) setError(e.message);
        });
    void load();
    const timer = setInterval(() => void load(), 15000);
    return () => {
      c.abort();
      clearInterval(timer);
    };
  }, []);
  return (
    <>
      {error && (
        <p role="alert" className="mx-4 text-sm text-destructive">
          恢复提醒暂不可用：{error}
        </p>
      )}
      {items.length > 0 && (
        <div role="alert" className="mx-4 rounded border border-amber-500 p-3 text-sm">
          <p>以下任务连续 3 次自动唤醒后仍无有效进展，需要人工检查：</p>
          {items.map((e) => (
            <Link key={e.id} href={`/function/tasks/detail?id=${e.task_id}`} className="mr-4 underline">
              任务 #{e.task_id}
            </Link>
          ))}
        </div>
      )}
    </>
  );
}
