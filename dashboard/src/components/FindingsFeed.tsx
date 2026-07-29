import type { Finding } from "@/lib/api";
import { SEVERITY_CLASSES, severityOf } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function FindingsFeed({ findings }: { findings: Finding[] }) {
  const real = findings.filter((f) => f.title !== "Out of scope" && f.title !== "No findings");

  return (
    <Card className="glass-panel flex h-full flex-col">
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-xl tracking-tight">Findings</CardTitle>
        <span className="text-sm font-bold text-primary">{real.length}</span>
      </CardHeader>
      <CardContent className="flex-1 space-y-2 overflow-y-auto">
        {real.length === 0 && (
          <p className="text-sm text-muted-foreground">No findings yet. Launch an engagement.</p>
        )}
        {real.map((f, i) => {
          const sev = severityOf(f);
          return (
            <div key={i} className="rounded-lg border border-white/5 bg-background/50 p-3 shadow-sm hover:shadow-md transition-shadow animate-slide-in-right hover:border-primary/20">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-semibold tracking-tight">{f.title}</span>
                {sev && <Badge className={`${SEVERITY_CLASSES[sev]} font-bold shadow-sm`}>{sev}</Badge>}
              </div>
              <p className="mt-2 text-xs text-muted-foreground leading-relaxed font-mono">{f.detail}</p>
              <div className="mt-3 flex flex-wrap gap-2 text-[10px] text-muted-foreground">
                <Badge className="border-white/10 bg-secondary/80 text-secondary-foreground hover:bg-secondary">{f.tool}</Badge>
                {f.cve && <Badge className="border-primary/30 bg-primary/10 text-primary hover:bg-primary/20">{f.cve}</Badge>}
                {f.cvss != null && <Badge className="border-orange-500/30 bg-orange-500/10 text-orange-400 hover:bg-orange-500/20">CVSS {f.cvss}</Badge>}
                {f.mitre && <Badge className="border-blue-500/30 bg-blue-500/10 text-blue-400 hover:bg-blue-500/20">{f.mitre}</Badge>}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
