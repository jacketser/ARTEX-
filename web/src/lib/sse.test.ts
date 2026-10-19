import assert from "node:assert/strict";
import { test } from "node:test";
import { TicketEventSource } from "./sse.ts";

class FakeSource extends EventTarget {
  static instances: FakeSource[] = [];
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  closed = false;
  constructor(public url: string) { super(); FakeSource.instances.push(this); }
  close() { this.closed = true; }
}
globalThis.EventSource = FakeSource as unknown as typeof EventSource;
const tick = () => new Promise((resolve) => setTimeout(resolve, 5));
test("reconnect obtains a new ticket and resumes from delivered cursor", async () => {
  const routes: string[] = [];
  const stream = new TicketEventSource("/api/exploration/activity/stream?task=1&since=0", async (path) => {
    routes.push(path); return `${path}&ticket=${routes.length}`;
  });
  await tick();
  const first = FakeSource.instances.at(-1)!;
  first.dispatchEvent(new MessageEvent("message", {data: "ok", lastEventId: "42"}));
  first.onerror?.(new Event("error"));
  await new Promise((resolve) => setTimeout(resolve, 1100));
  assert.equal(first.closed, true);
  assert.equal(routes.length, 2);
  assert.match(routes[1], /since=42/);
  assert.match(FakeSource.instances.at(-1)!.url, /ticket=2/);
  stream.close();
  assert.equal(FakeSource.instances.at(-1)!.closed, true);
});
test("unmount while acquiring ticket never opens a connection", async () => {
  let finish: ((url: string) => void) | undefined;
  const count = FakeSource.instances.length;
  const stream = new TicketEventSource("/api/logs/stream", () => new Promise((resolve) => { finish = resolve; }));
  stream.close(); finish!("/api/logs/stream?ticket=one"); await tick();
  assert.equal(FakeSource.instances.length, count);
});
