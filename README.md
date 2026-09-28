# FileDrop — Render-ready

This version intentionally keeps `index.html` in the repository root to avoid `public/` path mistakes.

## Local

```bash
npm install
npm start
```

Open `http://localhost:10000/`.

## Render

Create a **Web Service** (not a Static Site) connected to this repository.

- Root Directory: leave empty when these files are in the repository root
- Runtime: Node
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`

The server listens on `0.0.0.0` and uses Render's `PORT` automatically.

## GitHub and storage

Git does not keep empty directories. The repository therefore contains `.gitkeep` files in `storage/files/` and `storage/meta/`.

You do **not** need to upload actual files into `storage/`. The server creates the directories automatically on startup.

## Important free-plan limitation

Render Free Web Services have an ephemeral filesystem. Uploaded files may disappear after a restart, redeploy, or spin-down. This implementation is suitable for temporary/test sharing on the free plan, not durable storage.
