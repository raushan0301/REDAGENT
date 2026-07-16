import { ChevronRight } from "lucide-react";
import type { Finding } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const PHASES = ["recon", "scanning", "exploitation", "post-exploit"] as const;
const LABELS: Record<string, string> = {
  recon: "Recon",
  scanning: "Scanning",
  exploitation: "Exploitation",
  "post-exploit": "Post-Exploit",
};

export function ChainViz({ findings }: { findings: Finding[] }) {
  const byPhase = (phase: string) =>
    findings.filter((f) => f.phase === phase && f.title !== "Out of scope");

  return (
    <Card>
      <CardHeader>
        <CardTitle>Attack Chain</CardTitle>
      </CardHeader>
      <CardContent className="flex flex-wrap items-stretch gap-2">
        {PHASES.map((phase, i) => {
          const items = byPhase(phase);
          const active = items.length > 0;
          return (
            <div key={phase} className="flex items-stretch gap-2">
              <div
                className={`min-w-[130px] rounded-md border p-2 ${
                  active ? "border-primary/50 bg-primary/10" : "border-border bg-secondary/30 opacity-60"
                }`}
              >
                <div className="text-xs font-semibold">{LABELS[phase]}</div>
                <div className="mt-1 text-2xl font-bold">{items.length}</div>
                <div className="text-[10px] text-muted-foreground">findings</div>
              </div>
              {i < PHASES.length - 1 && (
                <ChevronRight className="h-5 w-5 self-center text-muted-foreground" />
              )}
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
