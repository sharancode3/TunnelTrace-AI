# TunnelTrace.AI · Editorial Frontend

This is a separate Next.js frontend. The original `frontend/` remains untouched and continues to be the route, feature, and API reference.

## Run

```powershell
npm install
npm run dev
```

The dev server uses port `3002`; configure `NEXT_PUBLIC_API_URL` only when the backend is not available at `http://127.0.0.1:8000/api/v1`.

The existing local API client, DTOs, analysis context, websocket hook, and feature routes are preserved in this copy. The new shell, presentation system, and command center are authored separately.
