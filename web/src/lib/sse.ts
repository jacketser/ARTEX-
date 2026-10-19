// Each reconnect needs a fresh one-use ticket. Preserve the last delivered cursor
// explicitly because replacing EventSource does not preserve Last-Event-ID.
export class TicketEventSource extends EventTarget {
  onopen: ((event: Event) => void) | null = null;
  onerror: ((event: Event) => void) | null = null;
  onmessage: ((event: MessageEvent) => void) | null = null;
  private source: EventSource | null = null;
  private closed = false;
  private cursor = "";
  private retries = 0;
  private timer: ReturnType<typeof setTimeout> | null = null;
  private request = new AbortController();

  constructor(private path: string, private ticketURL: (path: string, signal: AbortSignal) => Promise<string>) {
    super();
    void this.connect();
  }

  close() {
    this.closed = true;
    this.request.abort();
    this.source?.close();
    if (this.timer) clearTimeout(this.timer);
  }

  private reconnect() {
    if (this.closed) return;
    const delay = Math.min(30000, 1000 * 2 ** Math.min(this.retries++, 5));
    this.timer = setTimeout(() => void this.connect(), delay);
  }

  private async connect() {
    if (this.closed) return;
    try {
      const path = new URL(this.path, "http://localhost");
      if (this.cursor) path.searchParams.set("since", this.cursor);
      const url = await this.ticketURL(path.pathname + path.search, this.request.signal);
      if (this.closed) return;
      const source = new EventSource(url);
      this.source = source;
      source.onopen = (event) => {
        this.retries = 0;
        this.onopen?.(event);
        this.dispatchEvent(new Event("open"));
      };
      for (const type of ["message", "snapshot", "cleared"]) {
        source.addEventListener(type, (event) => {
          if (this.closed || this.source !== source) return;
          const message = event as MessageEvent;
          if (message.lastEventId) this.cursor = message.lastEventId;
          const copy = new MessageEvent(type, { data: message.data, lastEventId: message.lastEventId });
          if (type === "message") this.onmessage?.(copy);
          this.dispatchEvent(copy);
        });
      }
      source.onerror = (event) => {
        source.close();
        this.onerror?.(event);
        this.dispatchEvent(new Event("error"));
        this.reconnect();
      };
    } catch {
      if (this.closed) return;
      this.onerror?.(new Event("error"));
      this.dispatchEvent(new Event("error"));
      this.reconnect();
    }
  }
}
