import { useEffect, useState } from "react";
import { getHistory, type EngagementSummary } from "@/lib/api";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";

export function HistoryList({ onSelect }: { onSelect: (id: string) => void }) {
  const [history, setHistory] = useState<EngagementSummary[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    getHistory()
      .then((res) => {
        setHistory(res.engagements);
        setLoading(false);
      })
      .catch(() => {
        setHistory([]);
        setLoading(false);
      });
  }, []);

  return (
    <Card className="glass-panel flex flex-col h-full">
      <CardHeader className="flex-row items-center justify-between pb-2">
        <CardTitle className="text-xl tracking-tight">History</CardTitle>
        <span className="text-sm font-bold text-primary">{history.length} runs</span>
      </CardHeader>
      <CardContent className="flex-1 overflow-y-auto space-y-2">
        {loading ? (
          <p className="text-xs text-muted-foreground">Loading...</p>
        ) : history.length === 0 ? (
          <p className="text-xs text-muted-foreground">No past engagements.</p>
        ) : (
          history.map((eng) => (
            <div
              key={eng.id}
              className="cursor-pointer rounded-lg border border-white/5 bg-background/30 p-3 shadow-sm hover:shadow-md transition-all duration-300 hover:bg-secondary/40 hover:border-primary/20 hover:-translate-x-1"
              onClick={() => onSelect(eng.id)}
            >
              <div className="flex items-center justify-between">
                <span className="text-xs font-semibold">{eng.target}</span>
                <span className="text-[10px] text-muted-foreground">
                  {new Date(eng.last_updated).toLocaleDateString()}
                </span>
              </div>
              <p className="text-[10px] text-muted-foreground mt-1">
                {eng.id.slice(0, 8)} · {eng.num_findings} finding(s)
              </p>
            </div>
          ))
        )}
      </CardContent>
    </Card>
  );
}
