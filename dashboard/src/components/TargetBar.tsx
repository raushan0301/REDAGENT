import { Play, ShieldCheck } from "lucide-react";
import { useState } from "react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";

interface Props {
  scope: string;
  running: boolean;
  onLaunch: (target: string) => void;
}

export function TargetBar({ scope, running, onLaunch }: Props) {
  const [target, setTarget] = useState("");

  return (
    <div className="flex flex-wrap items-center gap-3 rounded-lg border bg-card p-3">
      <div className="flex items-center gap-2 text-primary">
        <ShieldCheck className="h-5 w-5" />
        <span className="text-lg font-bold tracking-tight">RedAgent</span>
      </div>
      <form
        className="flex flex-1 items-center gap-2"
        onSubmit={(e) => {
          e.preventDefault();
          if (target.trim() && !running) onLaunch(target.trim());
        }}
      >
        <Input
          placeholder="In-scope lab target (e.g. 10.0.0.5)"
          value={target}
          onChange={(e) => setTarget(e.target.value)}
        />
        <Button type="submit" disabled={running || !target.trim()}>
          <Play className="h-4 w-4" />
          {running ? "Running…" : "Launch"}
        </Button>
      </form>
      <Badge className="border-border bg-secondary text-secondary-foreground">
        Scope: {scope || "—"}
      </Badge>
    </div>
  );
}
