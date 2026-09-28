# FileDrop — v1 (0.10)

FileDrop is a temporary file-sharing service designed for a small Render Web Service. The repository is intentionally flat: `index.html`, `styles.css`, `app.js`, and `server.js` live in the repository root so Render can run `npm install` and `npm start` without a `public/` or subfolder configuration.

## Render

Create a **Web Service** connected to this repository.

- Root Directory: leave empty
- Build Command: `npm install`
- Start Command: `npm start`
- Health Check Path: `/healthz`

Render documents Node Web Services with `npm install`/`npm start` style commands and requires the app to bind to `0.0.0.0`. This project does both.

## Features

- Streamed uploads up to 2 GB per file
- Link expiry: 15 minutes, 1 hour, 6 hours, 24 hours, 7 days, or never
- Delete after first successful download
- Download limits: presets, custom 1–10,000, or unlimited
- Optional password protection
- Local browser profile with nickname/avatar/personalization
- Local upload/download history
- User search and online/offline presence
- Drop a share link into another user's inbox; recipients see it on their next visit while the service instance still has the inbox record
- Public share page with sender avatar fallback to the FileDrop logo
- SHA-256 security preflight before a share is released
- VirusTotal hash lookup can be enabled with `VT_API_KEY`; no private file is uploaded to VirusTotal automatically
- Direct VirusTotal lookup link is always provided from the SHA-256 hash
- Four-tap logo easter egg: 2000s-style visual mode
- Four-tap title easter egg: Windows XP-style title treatment
- Version/update dialog for new releases
- First-visit privacy/terms/instructions gate

## Security note about malware scanning

Without a VirusTotal API key, FileDrop does **not** claim to perform antivirus scanning. It computes the file's SHA-256 hash and shows a direct VirusTotal lookup link. With `VT_API_KEY` set, the server checks whether VirusTotal already has a verdict for the hash before returning the share. A hash lookup is not the same as uploading the file for a fresh multi-engine scan.

For a fully automatic scan of every new file, you would need an explicit malware-scanning service (or a ClamAV/ICAP setup) and enough storage/CPU for that workflow. This is intentionally not bundled into the free Render build.

## Storage warning

The app stores temporary files on the local filesystem. On Render Free, local filesystem data is not a durable object store and can be lost on redeploy/restart/spin-down. For durable production file storage, use object storage and a database.

## Environment variables

- `FILEDROP_SECRET` — optional stable HMAC secret for password-unlock cookies. Set this on Render so restarts don't invalidate every password session.
- `VT_API_KEY` — optional VirusTotal API key for hash lookups.

## Version

Current site version: **v1 (0.10)**.
