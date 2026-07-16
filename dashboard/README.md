# RedAgent Dashboard

Operator dashboard — React 19 + Vite + Tailwind + shadcn/ui-style components.
Talks to the FastAPI backend over REST + WebSocket for the live findings feed and
engagement status stream.

## Run

```bash
npm install
npm run dev            # http://localhost:5173 (proxies /engagements, /health, /ws -> :8000)
```

Start the backend alongside it: `uvicorn api.main:app --reload` (from repo root).

## Scripts

- `npm run dev` — dev server with API/WS proxy to uvicorn :8000
- `npm run build` — typecheck (`tsc --noEmit`) + production build
- `npm run typecheck` — types only

## Structure

```
src/
├── lib/
│   ├── api.ts          REST + WebSocket client + types (Finding, Engagement)
│   ├── severity.ts     CVSS -> severity banding, risk rating, colors
│   └── utils.ts        cn() classname helper
├── components/
│   ├── ui/             shadcn-style primitives (button, card, badge, input)
│   ├── TargetBar.tsx   target input + launch + scope badge
│   ├── ChainViz.tsx    recon -> scanning -> exploitation phase graph
│   ├── SeveritySummary.tsx   risk rating + severity counts
│   ├── FindingsFeed.tsx      live findings list with severity badges
│   └── ReasoningStream.tsx   engagement status/event log
├── App.tsx             wires panels to the API + WebSocket
└── main.tsx            entry
```

## Status

Scaffolded and building. Panels render and wire to the live API; the reasoning
stream currently shows engagement state transitions. Next: per-step reasoning
events from the backend, scope management UI, and one-click PDF export (needs a
report endpoint on the API).
