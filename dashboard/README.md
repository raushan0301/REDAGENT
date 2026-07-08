# RedAgent Dashboard

Operator dashboard — React 19 + shadcn/ui. Talks to the FastAPI backend over
WebSocket for the live reasoning stream and findings feed.

## Panels (Month 1 Week 4 → Month 2 Week 7)

- Target input + scope management (add/remove/list; server re-validates)
- Live attack-chain visualization (recon → scan → exploit graph)
- Agent reasoning stream (chain-of-thought as it happens)
- Findings feed (live vulnerability list)
- Session history
- One-click PDF report export

## Scaffold (not yet created)

```bash
npm create vite@latest . -- --template react-ts
npx shadcn@latest init
npm run dev
```

STUB — the React app has not been scaffolded yet. Use shadcn/ui components; no
ad-hoc CSS where a component exists (see CLAUDE.md conventions).
