import { Plus, X } from "lucide-react";
import { useState } from "react";
import { addScope, removeScope } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";

interface Props {
  scope: string[];
  onChange: (scope: string[]) => void;
}

export function ScopePanel({ scope, onChange }: Props) {
  const [entry, setEntry] = useState("");
  const [error, setError] = useState<string | null>(null);

  async function add() {
    if (!entry.trim()) return;
    try {
      const res = await addScope(entry.trim());
      onChange(res.scope);
      setEntry("");
      setError(null);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  async function remove(target: string) {
    try {
      const res = await removeScope(target);
      onChange(res.scope);
    } catch (e) {
      setError((e as Error).message);
    }
  }

  return (
    <Card>
      <CardHeader>
        <CardTitle>Scope</CardTitle>
      </CardHeader>
      <CardContent className="space-y-3">
        <form
          className="flex gap-2"
          onSubmit={(e) => {
            e.preventDefault();
            add();
          }}
        >
          <Input
            placeholder="10.0.0.0/24"
            value={entry}
            onChange={(e) => setEntry(e.target.value)}
          />
          <Button type="submit" variant="secondary" size="sm">
            <Plus className="h-4 w-4" />
            Add
          </Button>
        </form>
        {error && <p className="text-xs text-primary">{error}</p>}
        <div className="flex flex-wrap gap-2">
          {scope.length === 0 && (
            <p className="text-xs text-muted-foreground">
              No scope — all targets denied. Add a lab network to begin.
            </p>
          )}
          {scope.map((s) => (
            <Badge key={s} className="border-border bg-secondary gap-1 pr-1">
              {s}
              <button
                onClick={() => remove(s)}
                className="rounded p-0.5 hover:bg-primary/30"
                aria-label={`Remove ${s}`}
              >
                <X className="h-3 w-3" />
              </button>
            </Badge>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}
