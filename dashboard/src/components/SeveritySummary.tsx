import type { Finding } from "@/lib/api";
import { riskRating, SEVERITY_CLASSES, severityCounts, type Severity } from "@/lib/severity";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const SEVS: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  const counts = severityCounts(findings);
  return (
    <Card>
      <CardHeader className="flex-row items-center justify-between">
        <CardTitle>Risk</CardTitle>
        <span className="text-sm font-semibold text-primary">{riskRating(findings)}</span>
      </CardHeader>
      <CardContent className="grid grid-cols-5 gap-2">
        {SEVS.map((s) => (
          <div key={s} className={`rounded-md border px-2 py-3 text-center ${SEVERITY_CLASSES[s]}`}>
            <div className="text-xl font-bold">{counts[s]}</div>
            <div className="text-[10px] uppercase tracking-wide">{s}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
