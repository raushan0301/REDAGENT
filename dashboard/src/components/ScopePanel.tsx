import { Globe, Lock, Plus, RefreshCw, X, Wifi } from "lucide-react";
import { useCallback, useEffect, useRef, useState } from "react";
import {
  addPublicScope,
  addScope,
  getPublicScope,
  getScope,
  removePublicScope,
  removeScope,
} from "@/lib/api";

// ── Types ────────────────────────────────────────────────────────────────────

interface ScopeEntry {
  value: string;
  type: "lab" | "public";
  addedAt: string;
}

interface Props {
  /** Called whenever lab scope changes so parent (TargetBar) stays in sync */
  onLabScopeChange?: (scope: string[]) => void;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function timestamp() {
  return new Date().toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}

function isPublicIp(value: string): boolean {
  // Heuristic: if it contains a TLD dot or starts with non-RFC1918, treat as public
  const privateRanges = [/^10\./, /^172\.(1[6-9]|2\d|3[01])\./, /^192\.168\./, /^127\./];
  return !privateRanges.some((r) => r.test(value));
}

// ── Component ────────────────────────────────────────────────────────────────

export function ScopePanel({ onLabScopeChange }: Props) {
  const [labScope, setLabScope] = useState<ScopeEntry[]>([]);
  const [publicScope, setPublicScope] = useState<ScopeEntry[]>([]);
  const [activeTab, setActiveTab] = useState<"all" | "lab" | "public">("all");
  const [entry, setEntry] = useState("");
  const [isPublic, setIsPublic] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [lastRefresh, setLastRefresh] = useState(timestamp());
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // ── Fetch both scopes ─────────────────────────────────────────────────────

  const fetchScopes = useCallback(async (silent = false) => {
    if (!silent) setRefreshing(true);
    try {
      const [lab, pub] = await Promise.all([getScope(), getPublicScope()]);
      setLabScope(lab.scope.map((v) => ({ value: v, type: "lab", addedAt: timestamp() })));
      setPublicScope(pub.scope.map((v) => ({ value: v, type: "public", addedAt: timestamp() })));
      onLabScopeChange?.(lab.scope);
      setLastRefresh(timestamp());
    } catch {
      // silently ignore polling errors
    } finally {
      setRefreshing(false);
    }
  }, [onLabScopeChange]);

  // Initial load + polling every 15s
  useEffect(() => {
    fetchScopes();
    pollRef.current = setInterval(() => fetchScopes(true), 15_000);
    return () => { if (pollRef.current) clearInterval(pollRef.current); };
  }, [fetchScopes]);

  // Auto-detect public vs lab from input
  useEffect(() => {
    setIsPublic(entry.trim().length > 0 && isPublicIp(entry.trim()));
  }, [entry]);

  // ── Add entry ─────────────────────────────────────────────────────────────

  async function handleAdd() {
    const val = entry.trim();
    if (!val) return;
    setLoading(true);
    setError(null);
    try {
      if (isPublic) {
        const res = await addPublicScope(val);
        setPublicScope(res.scope.map((v) => ({ value: v, type: "public", addedAt: timestamp() })));
      } else {
        const res = await addScope(val);
        setLabScope(res.scope.map((v) => ({ value: v, type: "lab", addedAt: timestamp() })));
        onLabScopeChange?.(res.scope);
      }
      setEntry("");
      setLastRefresh(timestamp());
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  }

  // ── Remove entry ──────────────────────────────────────────────────────────

  async function handleRemove(s: ScopeEntry) {
    setError(null);
    try {
      if (s.type === "public") {
        const res = await removePublicScope(s.value);
        setPublicScope(res.scope.map((v) => ({ value: v, type: "public", addedAt: timestamp() })));
      } else {
        const res = await removeScope(s.value);
        setLabScope(res.scope.map((v) => ({ value: v, type: "lab", addedAt: timestamp() })));
        onLabScopeChange?.(res.scope);
      }
      setLastRefresh(timestamp());
    } catch (e) {
      setError((e as Error).message);
    }
  }

  // ── Derived list ──────────────────────────────────────────────────────────

  const allEntries: ScopeEntry[] = [...labScope, ...publicScope];
  const displayed =
    activeTab === "all" ? allEntries :
    activeTab === "lab" ? labScope :
    publicScope;

  const totalCount = allEntries.length;
  const labCount = labScope.length;
  const pubCount = publicScope.length;

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="rounded-xl border border-white/10 bg-white/5 backdrop-blur-md overflow-hidden shadow-xl">

      {/* ── Header ── */}
      <div className="px-4 pt-4 pb-3 border-b border-white/10">
        <div className="flex items-center justify-between mb-1">
          <div className="flex items-center gap-2">
            <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
            <span className="text-sm font-semibold text-white tracking-wide">Scope Manager</span>
          </div>
          <button
            onClick={() => fetchScopes()}
            disabled={refreshing}
            title="Refresh scope"
            className="p-1.5 rounded-lg hover:bg-white/10 transition-colors text-white/50 hover:text-white/90 disabled:opacity-40"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${refreshing ? "animate-spin" : ""}`} />
          </button>
        </div>
        <p className="text-[10px] text-white/30">Last sync: {lastRefresh} · auto-refreshes every 15s</p>

        {/* Stats row */}
        <div className="flex gap-3 mt-3">
          <StatChip label="Total" count={totalCount} color="indigo" />
          <StatChip label="Lab" count={labCount} color="cyan" />
          <StatChip label="Public" count={pubCount} color="amber" />
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="flex border-b border-white/10">
        {(["all", "lab", "public"] as const).map((tab) => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`flex-1 py-2 text-[11px] font-medium capitalize tracking-wide transition-colors ${
              activeTab === tab
                ? "text-white border-b-2 border-indigo-400 bg-white/5"
                : "text-white/40 hover:text-white/70"
            }`}
          >
            {tab === "all" ? `All (${totalCount})` : tab === "lab" ? `Lab (${labCount})` : `Public (${pubCount})`}
          </button>
        ))}
      </div>

      {/* ── Add form ── */}
      <div className="px-4 py-3 border-b border-white/10">
        <form
          className="flex gap-2"
          onSubmit={(e) => { e.preventDefault(); handleAdd(); }}
        >
          <div className="relative flex-1">
            <input
              value={entry}
              onChange={(e) => setEntry(e.target.value)}
              placeholder="10.0.0.0/24 or snaplocate.in"
              className="w-full bg-white/5 border border-white/15 rounded-lg px-3 py-1.5 text-xs text-white placeholder-white/25 focus:outline-none focus:border-indigo-400/60 focus:ring-1 focus:ring-indigo-400/30 transition-all pr-16"
            />
            {entry.trim() && (
              <span className={`absolute right-2 top-1/2 -translate-y-1/2 text-[9px] font-semibold px-1.5 py-0.5 rounded-full ${
                isPublic
                  ? "bg-amber-500/20 text-amber-300 border border-amber-500/30"
                  : "bg-cyan-500/20 text-cyan-300 border border-cyan-500/30"
              }`}>
                {isPublic ? "PUBLIC" : "LAB"}
              </span>
            )}
          </div>
          <button
            type="submit"
            disabled={loading || !entry.trim()}
            className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-indigo-500/80 hover:bg-indigo-500 text-white text-xs font-medium transition-all disabled:opacity-40 disabled:cursor-not-allowed shadow-lg shadow-indigo-500/20"
          >
            <Plus className="h-3.5 w-3.5" />
            Add
          </button>
        </form>
        {error && (
          <p className="mt-1.5 text-[10px] text-rose-400 flex items-center gap-1">
            <span className="inline-block w-1.5 h-1.5 rounded-full bg-rose-400" />
            {error}
          </p>
        )}
        {isPublic && entry.trim() && (
          <p className="mt-1.5 text-[10px] text-amber-400/80 flex items-center gap-1">
            <Globe className="h-3 w-3" />
            Detected as public target — will use authorized-public scope
          </p>
        )}
      </div>

      {/* ── Scope list ── */}
      <div className="px-4 py-3 space-y-2 max-h-72 overflow-y-auto scrollbar-thin">
        {displayed.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-6 gap-2 text-white/25">
            <Wifi className="h-8 w-8" />
            <p className="text-xs text-center">
              {activeTab === "all"
                ? "No scope entries — all targets denied"
                : activeTab === "lab"
                ? "No lab targets in scope"
                : "No authorized public targets"}
            </p>
          </div>
        ) : (
          displayed.map((s) => (
            <ScopeRow key={`${s.type}-${s.value}`} entry={s} onRemove={handleRemove} />
          ))
        )}
      </div>
    </div>
  );
}

// ── Sub-components ────────────────────────────────────────────────────────────

function StatChip({ label, count, color }: { label: string; count: number; color: string }) {
  const colors: Record<string, string> = {
    indigo: "bg-indigo-500/15 text-indigo-300 border-indigo-500/25",
    cyan:   "bg-cyan-500/15 text-cyan-300 border-cyan-500/25",
    amber:  "bg-amber-500/15 text-amber-300 border-amber-500/25",
  };
  return (
    <div className={`flex items-center gap-1.5 px-2.5 py-1 rounded-full border text-[10px] font-medium ${colors[color]}`}>
      <span>{label}</span>
      <span className="font-bold">{count}</span>
    </div>
  );
}

function ScopeRow({
  entry,
  onRemove,
}: {
  entry: ScopeEntry;
  onRemove: (e: ScopeEntry) => void;
}) {
  const isPublicEntry = entry.type === "public";
  return (
    <div className={`group flex items-center justify-between gap-2 px-3 py-2 rounded-lg border transition-all ${
      isPublicEntry
        ? "bg-amber-500/8 border-amber-500/20 hover:bg-amber-500/12"
        : "bg-cyan-500/8 border-cyan-500/20 hover:bg-cyan-500/12"
    }`}>
      <div className="flex items-center gap-2 min-w-0">
        {isPublicEntry ? (
          <Globe className="h-3.5 w-3.5 text-amber-400 shrink-0" />
        ) : (
          <Lock className="h-3.5 w-3.5 text-cyan-400 shrink-0" />
        )}
        <span className="text-xs text-white font-mono truncate">{entry.value}</span>
      </div>
      <div className="flex items-center gap-2 shrink-0">
        <span className={`text-[9px] px-1.5 py-0.5 rounded-full border font-semibold ${
          isPublicEntry
            ? "bg-amber-500/20 text-amber-300 border-amber-500/30"
            : "bg-cyan-500/20 text-cyan-300 border-cyan-500/30"
        }`}>
          {isPublicEntry ? "PUBLIC" : "LAB"}
        </span>
        <button
          onClick={() => onRemove(entry)}
          title={`Remove ${entry.value}`}
          className="opacity-0 group-hover:opacity-100 p-1 rounded-md hover:bg-rose-500/20 text-white/30 hover:text-rose-400 transition-all"
        >
          <X className="h-3.5 w-3.5" />
        </button>
      </div>
    </div>
  );
}
