import type { Finding } from "@/lib/api";
import { SEVERITY_CLASSES, severityOf } from "@/lib/severity";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function FindingsFeed({ findings }: { findings: Finding[] }) {
  const real = findings.filter((f) => f.title !== "Out of scope" && f.title !== "No findings");

  return (
    <Card className="flex h-full flex-col">
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Findings</CardTitle>
        <span className="text-xs text-muted-foreground">{real.length}</span>
      </CardHeader>
      <CardContent className="flex-1 space-y-2 overflow-y-auto">
        {real.length === 0 && (
          <p className="text-sm text-muted-foreground">No findings yet. Launch an engagement.</p>
        )}
        {real.map((f, i) => {
          const sev = severityOf(f);
          return (
            <div key={i} className="rounded-md border bg-background/30 p-2">
              <div className="flex items-center justify-between gap-2">
                <span className="text-sm font-medium">{f.title}</span>
                {sev && <Badge className={SEVERITY_CLASSES[sev]}>{sev}</Badge>}
              </div>
              <p className="mt-1 text-xs text-muted-foreground">{f.detail}</p>
              <div className="mt-1 flex flex-wrap gap-1.5 text-[10px] text-muted-foreground">
                <Badge className="border-border bg-secondary/50">{f.tool}</Badge>
                {f.cve && <Badge className="border-border bg-secondary/50">{f.cve}</Badge>}
                {f.cvss != null && <Badge className="border-border bg-secondary/50">CVSS {f.cvss}</Badge>}
                {f.mitre && <Badge className="border-border bg-secondary/50">{f.mitre}</Badge>}
              </div>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}
