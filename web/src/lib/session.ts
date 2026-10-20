// Short-lived access token; the refresh credential is only in an HttpOnly cookie.
const key = "artex_token";
let refreshing: Promise<boolean> | null = null;
let generation = 0;
if (typeof window !== "undefined") {
  window.addEventListener("storage", (event) => {
    if (event.key === key && event.newValue === null) {
      generation++;
      if (!location.pathname.startsWith("/login") && !location.pathname.startsWith("/setup"))
        window.location.href = "/login";
    }
  });
}
export function saveAccessToken(token: string) {
  localStorage.setItem(key, token);
  document.cookie = `${key}=${encodeURIComponent(token)}; path=/; max-age=900; SameSite=Strict${location.protocol === "https:" ? "; Secure" : ""}`;
}
export function clearAccessToken() {
  generation++;
  localStorage.removeItem(key);
  document.cookie = `${key}=; path=/; max-age=0`;
}
function freshToken(token: string | null) {
  if (!token) return false;
  if (process.env.NEXT_PUBLIC_MOCK === "1") return true;
  try {
    return JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/"))).exp * 1000 > Date.now() + 30000;
  } catch {
    return false;
  }
}
export async function ensureSession(force = false, failedToken?: string | null): Promise<boolean> {
  if (typeof window === "undefined") return false;
  if (process.env.NEXT_PUBLIC_MOCK === "1") return true;
  const current = localStorage.getItem(key);
  if (freshToken(current) && (!force || (failedToken !== undefined && current !== failedToken))) return true;
  if (refreshing) return refreshing;
  const epoch = generation;
  const run = async () => {
    const latest = localStorage.getItem(key);
    if (freshToken(latest) && (!force || (failedToken !== undefined && latest !== failedToken))) return true;
    const r = await fetch("/api/auth/refresh", {
      method: "POST",
      credentials: "same-origin",
      signal: AbortSignal.timeout(15000),
      headers: { "X-ARTEX-Session": "1" },
    });
    if (r.status === 401) {
      if (generation === epoch) clearAccessToken();
      return false;
    }
    if (!r.ok) throw new Error("登录续期暂时不可用，请稍后重试");
    const { token } = await r.json();
    if (generation !== epoch) return false;
    saveAccessToken(token);
    return true;
  };
  // Web Locks coordinate tabs. The server also tolerates simultaneous retries.
  const pending: Promise<boolean> = (async () =>
    navigator.locks ? await navigator.locks.request("artex-session", run) : await run())();
  refreshing = pending.finally(() => {
    refreshing = null;
  });
  return refreshing;
}
export async function authenticatedFetch(input: string, init?: RequestInit): Promise<Response> {
  if (!(await ensureSession())) {
    window.location.href = "/login";
    throw new Error("请重新登录");
  }
  const send = () => {
    const headers = new Headers(init?.headers);
    const token = localStorage.getItem(key);
    if (token) headers.set("Authorization", `Bearer ${token}`);
    return fetch(input, { ...init, headers, credentials: "same-origin" });
  };
  const used = localStorage.getItem(key);
  let r = await send();
  if (r.status === 401 && !init?.signal?.aborted) {
    if (await ensureSession(true, used)) r = await send();
    else {
      window.location.href = "/login";
    }
  }
  return r;
}
export async function logoutSession() {
  generation++;
  if (refreshing) await refreshing.catch(() => false);
  const run = async () => {
    const r = await fetch("/api/auth/logout", {
      method: "POST",
      credentials: "same-origin",
      signal: AbortSignal.timeout(15000),
      headers: { "X-ARTEX-Session": "1" },
    });
    if (!r.ok) throw new Error("退出登录失败，请重试");
    clearAccessToken();
  };
  if (navigator.locks) await navigator.locks.request("artex-session", run);
  else await run();
}
