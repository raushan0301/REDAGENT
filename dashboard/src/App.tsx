import { FileDown } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import { ChainViz } from "@/components/ChainViz";
import { FindingsFeed } from "@/components/FindingsFeed";
import { ReasoningStream, type LogLine } from "@/components/ReasoningStream";
import { ScopePanel } from "@/components/ScopePanel";
import { SeveritySummary } from "@/components/SeveritySummary";
import { TargetBar } from "@/components/TargetBar";
import { Button } from "@/components/ui/button";
import {
  connectEngagement,
  downloadReport,
  getHealth,
  getScope,
  startEngagement,
  type Engagement,
} from "@/lib/api";

function now(): string {
  return new Date().toLocaleTimeString();
}

export default function App() {
  const [scopeSummary, setScopeSummary] = useState("");
  const [scope, setScope] = useState<string[]>([]);
  const [engagement, setEngagement] = useState<Engagement | null>(null);
  const [log, setLog] = useState<LogLine[]>([]);
  const wsRef = useRef<WebSocket | null>(null);

  useEffect(() => {
    getHealth().then((h) => setScopeSummary(h.scope)).catch(() => setScopeSummary("backend offline"));
    getScope().then((s) => setScope(s.scope)).catch(() => setScope([]));
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
        wsRef.current = connectEngagement(eng.id, (frame) => {
          if (frame.type === "status") {
            setEngagement(frame);
            append(
              `State: ${frame.state} — ${frame.findings.length} finding(s).` +
                (frame.error ? ` Error: ${frame.error}` : ""),
            );
          } else {
            append(`[${frame.type}] ${frame.text}`);
          }
        });
      } catch (err) {
        append(`Refused: ${(err as Error).message}`);
      }
    },
    [append],
  );

  const onExport = useCallback(async () => {
    if (!engagement) return;
    append("Generating PDF report…");
    try {
      await downloadReport(engagement.id);
      append("Report downloaded.");
    } catch (err) {
      append(`Report failed: ${(err as Error).message}`);
    }
  }, [engagement, append]);

  const findings = engagement?.findings ?? [];
  const canExport = engagement?.state === "done" && findings.length > 0;

  return (
    <div className="mx-auto max-w-7xl space-y-4 p-4">
      <TargetBar scope={scopeSummary} running={running} onLaunch={onLaunch} />

      <div className="grid gap-4 lg:grid-cols-3">
        <div className="space-y-4 lg:col-span-2">
          <ChainViz findings={findings} />
          <SeveritySummary findings={findings} />
          <div className="flex justify-end">
            <Button variant="outline" size="sm" disabled={!canExport} onClick={onExport}>
              <FileDown className="h-4 w-4" />
              Export PDF
            </Button>
          </div>
          <FindingsFeed findings={findings} />
        </div>
        <div className="space-y-4 lg:col-span-1">
          <ScopePanel scope={scope} onChange={setScope} />
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
