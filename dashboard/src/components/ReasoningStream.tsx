import { Activity } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export interface LogLine {
  ts: string;
  text: string;
}

export function ReasoningStream({ log }: { log: LogLine[] }) {
  return (
    <Card className="flex h-full flex-col">
      <CardHeader className="flex-row items-center gap-2">
        <Activity className="h-4 w-4 text-primary" />
        <CardTitle>Reasoning Stream</CardTitle>
      </CardHeader>
      <CardContent className="flex-1 space-y-1 overflow-y-auto font-mono text-xs">
        {log.length === 0 && <p className="text-muted-foreground">Idle.</p>}
        {log.map((l, i) => (
          <div key={i} className="flex gap-2">
            <span className="text-muted-foreground">{l.ts}</span>
            <span>{l.text}</span>
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
