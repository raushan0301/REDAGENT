import type { Finding } from "@/lib/api";
import { riskRating, SEVERITY_CLASSES, severityCounts, type Severity } from "@/lib/severity";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

const SEVS: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export function SeveritySummary({ findings }: { findings: Finding[] }) {
  const counts = severityCounts(findings);
  return (
    <Card className="glass-panel border-transparent hover:border-primary/20 transition-all duration-300">
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-xl tracking-tight">Risk Profile</CardTitle>
        <span className={`text-lg font-bold ${riskRating(findings) === "Critical" ? "text-primary text-glow animate-pulse-glow" : "text-primary"}`}>{riskRating(findings)}</span>
      </CardHeader>
      <CardContent className="grid grid-cols-5 gap-3 pt-4">
        {SEVS.map((s) => (
          <div key={s} className={`rounded-xl border px-2 py-4 flex flex-col items-center justify-center transition-all duration-300 hover:-translate-y-1 hover:shadow-lg ${SEVERITY_CLASSES[s]} ${counts[s] > 0 ? "opacity-100" : "opacity-60 grayscale-[50%]"}`}>
            <div className={`text-2xl font-black tabular-nums ${counts[s] > 0 && (s === "Critical" || s === "High") ? "text-glow" : ""}`}>{counts[s]}</div>
            <div className="text-[10px] uppercase tracking-wider font-semibold mt-1">{s}</div>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
