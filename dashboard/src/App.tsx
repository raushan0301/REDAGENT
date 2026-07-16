import { useCallback, useEffect, useRef, useState } from "react";
import { ChainViz } from "@/components/ChainViz";
import { FindingsFeed } from "@/components/FindingsFeed";
import { ReasoningStream, type LogLine } from "@/components/ReasoningStream";
import { SeveritySummary } from "@/components/SeveritySummary";
import { TargetBar } from "@/components/TargetBar";
import {
  connectEngagement,
  getHealth,
  startEngagement,
  type Engagement,
} from "@/lib/api";

function now(): string {
  return new Date().toLocaleTimeString();
}

export default function App() {
  const [scope, setScope] = useState("");
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    getHealth().then((h) => setScope(h.scope)).catch(() => setScope("backend offline"));
    return () => wsRef.current?.close();
  }, []);

  const append = useCallback((text: string) => {
    setLog((prev) => [...prev, { ts: now(), text }].slice(-200));
  }, []);

  const running = engagement?.state === "running";

  const onLaunch = useCallback(
    async (target: string) => {
      setLog([]);
      append(`Launching engagement against ${target}…`);
      try {
        const eng = await startEngagement(target);
        setEngagement(eng);
        append(`Engagement ${eng.id.slice(0, 8)} started (state: ${eng.state}).`);
        wsRef.current?.close();
        wsRef.current = connectEngagement(eng.id, (update) => {
          setEngagement(update);
          append(
            `State: ${update.state} — ${update.findings.length} finding(s).` +
              (update.error ? ` Error: ${update.error}` : ""),
          );
        });
      } catch (err) {
        append(`Refused: ${(err as Error).message}`);
      }
    },
    [append],
  );

  const findings = engagement?.findings ?? [];

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4">
      <TargetBar scope={scope} running={running} onLaunch={onLaunch} />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <ChainViz findings={findings} />
          <SeveritySummary findings={findings} />
          <FindingsFeed findings={findings} />
        </div>
        <div className="lg:col-span-1">
          <ReasoningStream log={log} />
        </div>
      </div>

      {engagement && (
        <p className="text-center text-xs text-muted-foreground">
          Engagement {engagement.id} · target {engagement.target} · {engagement.state}
        </p>
      )}
    </div>
  );
}
