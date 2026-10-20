"use client";
import * as React from "react";
import { http } from "@/lib/api";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Switch } from "@/components/ui/switch";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { toast } from "sonner";

function useConfig<T>(path: string) {
  const [value, setValue] = React.useState<T | null>(null),
    [error, setError] = React.useState(""),
    [busy, setBusy] = React.useState(false);
  React.useEffect(() => {
    const c = new AbortController();
    http<T>(path, { signal: c.signal })
      .then(setValue)
      .catch((e) => {
        if (!c.signal.aborted) setError(e.message);
      });
    return () => c.abort();
  }, [path]);
  async function save() {
    setBusy(true);
    try {
      setValue(await http<T>(path, { method: "PUT", body: JSON.stringify(value) }));
      setError("");
      toast.success("配置已保存");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  return { value, setValue, error, busy, save };
}
type FreezeConfig = { enabled: boolean; threshold_seconds: number; max_compensation_seconds: number };
type ClockEvent = { id: number; observed_at: string; shift_seconds: number; reason: string; affected_tasks: string[] };
export function FreezeSettings() {
  const c = useConfig<FreezeConfig>("/settings/freeze-compensation");
  const [events, setEvents] = React.useState<ClockEvent[]>([]),
    [error, setError] = React.useState(""),
    [more, setMore] = React.useState(false),
    [loading, setLoading] = React.useState(false);
  const load = React.useCallback(async (before = 0) => {
    setLoading(true);
    try {
      const rows = await http<ClockEvent[]>("/clock-compensations?before=" + before);
      setEvents((prev) => (before ? [...prev, ...rows] : rows));
      setMore(rows.length === 50);
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }, []);
  React.useEffect(() => {
    void load();
  }, [load]);
  const labels: Record<string, string> = {
    scheduler_gap: "疑似进程停顿",
    wall_clock_jump: "系统时钟跳变",
    scheduler_gap_disabled: "进程停顿（补偿已关闭）",
    wall_clock_jump_disabled: "时钟跳变（补偿已关闭）",
    scheduler_gap_exceeds_limit: "进程停顿（超过补偿上限）",
    wall_clock_jump_exceeds_limit: "时钟跳变（超过补偿上限）",
  };
  return (
    <Card className="mb-4 break-inside-avoid">
      <CardHeader>
        <CardTitle>服务器冻结补偿</CardTitle>
        <CardDescription>
          检测进程运行期间的长时间停顿与时钟跳变，为当时正在运行的任务调整截止时间并留存记录。暂停、排队、终态及已过期任务不补偿；重启停机时间不自动补偿。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {c.error && <p role="alert">{c.error}</p>}
        {c.value && (
          <fieldset disabled={c.busy} className="space-y-3">
            <label className="flex items-center gap-2">
              <Switch
                aria-label="启用冻结补偿"
                checked={c.value.enabled}
                onCheckedChange={(enabled) => c.setValue({ ...c.value!, enabled })}
              />
              启用补偿
            </label>
            <label className="block">
              异常阈值（秒）
              <Input
                aria-label="冻结异常阈值"
                type="number"
                min={30}
                max={3600}
                value={c.value.threshold_seconds}
                onChange={(e) => c.setValue({ ...c.value!, threshold_seconds: Number(e.target.value) })}
              />
            </label>
            <label className="block">
              单次补偿上限（秒）
              <Input
                aria-label="冻结补偿上限"
                type="number"
                min={30}
                max={604800}
                value={c.value.max_compensation_seconds}
                onChange={(e) => c.setValue({ ...c.value!, max_compensation_seconds: Number(e.target.value) })}
              />
            </label>
            <p className="text-xs text-muted-foreground">
              超过上限只记录，不自动顺延。任务截止可调整；单次模型调用与 Worker
              自身运行时限仍独立生效。配置对之后启动的运行轮次生效。
            </p>
            <Button size="sm" onClick={() => void c.save()}>
              保存冻结补偿设置
            </Button>
          </fieldset>
        )}
        <details>
          <summary>时钟补偿记录（{events.length} 条）</summary>
          <Button size="sm" variant="outline" disabled={loading} onClick={() => void load()}>
            刷新补偿记录
          </Button>
          {error && <p role="alert">{error}</p>}
          {events.map((e) => (
            <p key={e.id} className="my-2 text-xs">
              {new Date(e.observed_at).toLocaleString("zh-CN")} · {labels[e.reason] ?? e.reason} ·{" "}
              {e.shift_seconds > 0 ? "+" : ""}
              {e.shift_seconds} 秒 · {e.affected_tasks.length} 个任务
              {e.affected_tasks.length ? "（" + e.affected_tasks.join("、") + "）" : ""}
            </p>
          ))}
          {more && (
            <Button size="sm" disabled={loading} onClick={() => void load(events.at(-1)?.id)}>
              加载更早补偿
            </Button>
          )}
        </details>
      </CardContent>
    </Card>
  );
}
type Rule = { id: string; pattern: string; provider: string; source: string; match: string; fields: string[] };
export function HoneyRulesSettings() {
  const c = useConfig<{ rules: Rule[] }>("/settings/honeypot-rules");
  const fields = [
    "service",
    "title",
    "technologies",
    "banner",
    "server_header",
    "powered_by",
    "response_summary",
    "tls_subject",
    "tls_issuer",
    "tls_fingerprint",
  ];
  function change(i: number, patch: Partial<Rule>) {
    c.setValue({ rules: c.value!.rules.map((v, n) => (n === i ? { ...v, ...patch } : v)) });
  }
  return (
    <Card className="mb-4 break-inside-avoid">
      <CardHeader>
        <CardTitle>蜜罐识别规则</CardTitle>
        <CardDescription>
          管理已保存元数据的匹配规则与来源。保存后后台重评服务资产，旧人工结论需重新确认。TLS 字段来自资产 extra
          中已保存的证书信息。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {c.error && <p role="alert">{c.error}</p>}
        {c.value && (
          <fieldset disabled={c.busy} className="space-y-3">
            <details>
              <summary>编辑规则（{c.value.rules.length} 条）</summary>
              {c.value.rules.map((v, i) => (
                <div key={i} className="my-3 space-y-2 rounded border p-3">
                  {(["id", "provider", "pattern", "source"] as const).map((k) => (
                    <label className="block text-xs" key={k}>
                      {{ id: "规则 ID", provider: "产品名称", pattern: "匹配内容", source: "规则来源与依据" }[k]}
                      <Input
                        aria-label={"规则 " + (i + 1) + " " + k}
                        value={v[k]}
                        onChange={(e) => change(i, { [k]: e.target.value })}
                      />
                    </label>
                  ))}
                  <label>
                    匹配方式
                    <select
                      aria-label={"规则 " + (i + 1) + " 匹配方式"}
                      value={v.match}
                      onChange={(e) => change(i, { match: e.target.value })}
                      className="ml-2 border bg-background"
                    >
                      <option value="token">完整词</option>
                      <option value="contains">包含</option>
                      <option value="exact">完全一致</option>
                    </select>
                  </label>
                  <p className="text-xs">匹配字段（全不选表示全部字段）：</p>
                  <div className="flex flex-wrap gap-2">
                    {fields.map((f) => (
                      <label key={f} className="text-xs">
                        <input
                          type="checkbox"
                          checked={v.fields.includes(f)}
                          onChange={(e) =>
                            change(i, { fields: e.target.checked ? [...v.fields, f] : v.fields.filter((x) => x !== f) })
                          }
                        />
                        {f}
                      </label>
                    ))}
                  </div>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => c.setValue({ rules: c.value!.rules.filter((_, n) => n !== i) })}
                  >
                    删除规则 {i + 1}
                  </Button>
                </div>
              ))}
              <Button
                size="sm"
                variant="outline"
                disabled={c.value.rules.length >= 100}
                onClick={() =>
                  c.setValue({
                    rules: [
                      ...c.value!.rules,
                      { id: "", provider: "", pattern: "", source: "", match: "token", fields: [] },
                    ],
                  })
                }
              >
                新增规则
              </Button>
            </details>
            <Button size="sm" onClick={() => void c.save()}>
              保存蜜罐规则并重评
            </Button>
            <p className="text-xs text-muted-foreground">
              匹配最多 100 条规则，不支持正则；规则命中是待核对线索，不证明目标一定是蜜罐。
            </p>
          </fieldset>
        )}
      </CardContent>
    </Card>
  );
}
type Profile = { key: string; name: string; prompt: string; pivot: string };
type ScenarioConfig = { enabled: boolean; max_categories: number; max_chars: number; profiles: Profile[] };
type Preview = { tags: string[]; source: string; text: string; truncated: boolean };
export function ScenarioSettings() {
  const c = useConfig<ScenarioConfig>("/settings/scenario-prompts");
  const [summary, setSummary] = React.useState("核对 Web API 权限与证据"),
    [preview, setPreview] = React.useState<Preview | null>(null),
    [error, setError] = React.useState(""),
    [busy, setBusy] = React.useState(false);
  async function test() {
    setBusy(true);
    try {
      setPreview(
        await http<Preview>("/settings/scenario-prompts/preview", {
          method: "POST",
          body: JSON.stringify({ summary }),
        }),
      );
      setError("");
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  function change(i: number, patch: Partial<Profile>) {
    c.setValue({ ...c.value!, profiles: c.value!.profiles.map((v, n) => (n === i ? { ...v, ...patch } : v)) });
  }
  return (
    <Card className="mb-4 break-inside-avoid">
      <CardHeader>
        <CardTitle>场景化提示词</CardTitle>
        <CardDescription>
          按意图标签优先选择场景；没有标签时按摘要关键词选择，最后回退到证据复盘。每轮最多两类，活动记录展示实际选择；场景指导不扩大授权范围。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-3">
        {c.error && <p role="alert">{c.error}</p>}
        {c.value && (
          <fieldset disabled={c.busy} className="space-y-3">
            <label className="flex items-center gap-2">
              <Switch
                aria-label="启用场景提示词"
                checked={c.value.enabled}
                onCheckedChange={(enabled) => c.setValue({ ...c.value!, enabled })}
              />
              启用场景指导
            </label>
            <label className="block">
              每轮类别上限
              <Input
                aria-label="场景类别上限"
                type="number"
                min={1}
                max={2}
                value={c.value.max_categories}
                onChange={(e) => c.setValue({ ...c.value!, max_categories: Number(e.target.value) })}
              />
            </label>
            <label className="block">
              提示总字符上限
              <Input
                aria-label="场景字符上限"
                type="number"
                min={256}
                max={8000}
                value={c.value.max_chars}
                onChange={(e) => c.setValue({ ...c.value!, max_chars: Number(e.target.value) })}
              />
            </label>
            <details>
              <summary>编辑场景（{c.value.profiles.length} 类）</summary>
              {c.value.profiles.map((v, i) => (
                <div key={v.key} className="my-3 space-y-2 rounded border p-3">
                  <p>
                    {v.name} · {v.key}
                  </p>
                  <label className="block">
                    核对指导
                    <Textarea
                      aria-label={v.key + " 场景指导"}
                      value={v.prompt}
                      onChange={(e) => change(i, { prompt: e.target.value })}
                    />
                  </label>
                  <label className="block">
                    停滞时核对
                    <Textarea
                      aria-label={v.key + " 停滞提示"}
                      value={v.pivot}
                      onChange={(e) => change(i, { pivot: e.target.value })}
                    />
                  </label>
                </div>
              ))}
            </details>
            <Button size="sm" onClick={() => void c.save()}>
              保存场景提示词
            </Button>
          </fieldset>
        )}
        <label className="block">
          预览意图
          <Input aria-label="预览意图" value={summary} onChange={(e) => setSummary(e.target.value)} />
        </label>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => void test()}>
          预览已保存的场景配置
        </Button>
        {error && <p role="alert">{error}</p>}
        {preview && (
          <div className="space-y-2 text-xs">
            <p>
              选择：{preview.tags.join("、") || "未启用"} · {preview.source}
              {preview.truncated ? " · 已截断" : ""}
            </p>
            <pre className="whitespace-pre-wrap break-words">{preview.text}</pre>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
