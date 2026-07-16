import type { Finding } from "./api";

export type Severity = "Critical" | "High" | "Medium" | "Low" | "Info";

const ORDER: Severity[] = ["Critical", "High", "Medium", "Low", "Info"];

export function severityOf(f: Finding): Severity | null {
  if (f.severity && ORDER.includes(f.severity as Severity)) return f.severity as Severity;
  const s = f.cvss;
  if (s == null) return f.severity ? "Info" : null;
  if (s >= 9) return "Critical";
  if (s >= 7) return "High";
  if (s >= 4) return "Medium";
  if (s > 0) return "Low";
  return null;
}

export function severityCounts(findings: Finding[]): Record<Severity, number> {
  const counts: Record<Severity, number> = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
  for (const f of findings) {
    const sev = severityOf(f);
    if (sev) counts[sev] += 1;
  }
  return counts;
}

export function riskRating(findings: Finding[]): string {
  const counts = severityCounts(findings);
  for (const sev of ORDER) if (counts[sev]) return sev === "Info" ? "Informational" : sev;
  return "Informational";
}

export const SEVERITY_CLASSES: Record<Severity, string> = {
  Critical: "bg-red-600/20 text-red-300 border-red-600/40",
  High: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  Medium: "bg-yellow-500/20 text-yellow-200 border-yellow-500/40",
  Low: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  Info: "bg-slate-500/20 text-slate-300 border-slate-500/40",
};
