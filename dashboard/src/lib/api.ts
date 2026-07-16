// API client for the RedAgent FastAPI backend. In dev, Vite proxies these paths
// to uvicorn on :8000 (see vite.config.ts).

export interface Finding {
  tool: string;
  phase: string;
  target: string;
  title: string;
  detail: string;
  service?: string | null;
  version?: string | null;
  cve?: string | null;
  cvss?: number | null;
  severity?: string | null;
  evidence?: string | null;
  mitre?: string | null;
}

export interface Engagement {
  id: string;
  target: string;
  state: "queued" | "running" | "done" | "error";
  findings: Finding[];
  error?: string | null;
}

export interface Health {
  status: string;
  scope: string;
}

async function json<T>(res: Response): Promise<T> {
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`);
  }
  return res.json() as Promise<T>;
}

export function getHealth(): Promise<Health> {
  return fetch("/health").then(json<Health>);
}

export function startEngagement(target: string, allowDestructive = false): Promise<Engagement> {
  return fetch("/engagements", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ target, allow_destructive: allowDestructive }),
  }).then(json<Engagement>);
}

export function getEngagement(id: string): Promise<Engagement> {
  return fetch(`/engagements/${id}`).then(json<Engagement>);
}

export interface ScopeList {
  scope: string[];
}

export function getScope(): Promise<ScopeList> {
  return fetch("/scope").then(json<ScopeList>);
}

export function addScope(entry: string): Promise<ScopeList> {
  return fetch("/scope", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ entry }),
  }).then(json<ScopeList>);
}

export function removeScope(entry: string): Promise<ScopeList> {
  return fetch("/scope", {
    method: "DELETE",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ entry }),
  }).then(json<ScopeList>);
}

/** POST the report endpoint and trigger a browser download of the PDF. */
export async function downloadReport(id: string): Promise<void> {
  const res = await fetch(`/engagements/${id}/report`, { method: "POST" });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error((body as { detail?: string }).detail ?? `HTTP ${res.status}`);
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `redagent-${id}.pdf`;
  a.click();
  URL.revokeObjectURL(url);
}

export type StatusFrame = { type: "status" } & Engagement;
export type EventFrame = { type: "reason" | "act" | "observe"; step?: number; text: string };
export type WsFrame = StatusFrame | EventFrame;

/** Open a WebSocket for live engagement frames (status + reasoning events).
 * Returns the socket so callers can close it on unmount. */
export function connectEngagement(id: string, onFrame: (f: WsFrame) => void): WebSocket {
  const proto = location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${proto}//${location.host}/ws/${id}`);
  ws.onmessage = (evt) => {
    try {
      const data = JSON.parse(evt.data) as Partial<WsFrame>;
      if (data && data.type) onFrame(data as WsFrame);
    } catch {
      /* ignore malformed frames */
    }
  };
  return ws;
}
