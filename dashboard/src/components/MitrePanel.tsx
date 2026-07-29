import type { Finding } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function MitrePanel({ findings }: { findings: Finding[] }) {
  // Extract unique MITRE tactic/technique strings
  const mitreCodes = Array.from(
    new Set(
      findings
        .map((f) => f.mitre)
        .filter((m): m is string => Boolean(m))
    )
  ).sort();

  return (
    <Card className="glass-panel flex flex-col">
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-xl tracking-tight">MITRE ATT&CK</CardTitle>
        <span className="text-sm font-bold text-primary">{mitreCodes.length}</span>
      </CardHeader>
      <CardContent>
        {mitreCodes.length === 0 ? (
          <p className="text-xs text-muted-foreground">No MITRE tactics found.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {mitreCodes.map((code) => (
              <Badge key={code} className="border-primary/20 bg-primary/10 text-primary px-3 py-1 text-xs hover:bg-primary/20 hover:scale-105 transition-all duration-300 cursor-default">
                {code}
              </Badge>
            ))}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
