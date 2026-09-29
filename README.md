# FileDrop — v1 (0.15) / 2000s Update

FileDrop is a temporary file-sharing service designed for Render. The project intentionally avoids runtime npm dependencies so a clean Render deploy can run `npm install` without needing a package registry dependency tree.

## Render

Create a **Web Service** from the repository root.

- Build Command: `npm install`
- Start Command: `npm start`
- Root Directory: leave empty

`server.js` listens on Render's `PORT` and `0.0.0.0`.

## Upload path

Uploads are sent as a raw request body rather than multipart form-data. The browser sends small configuration headers while the file bytes stream directly into temporary storage. This keeps a 2 GB upload out of RAM.

## Optional VirusTotal lookup

Set `VT_API_KEY` as a Render environment variable to enable SHA-256 lookups against VirusTotal. Without the key, FileDrop still generates a SHA-256 hash and provides a VirusTotal link for manual checking.

## Storage note

The included `storage/` directory is temporary local storage. On Render Free, local files are not durable across service resets/redeploys/spin-down. For durable file retention, use an external object store in a future update.

## Secret

For stable password-session signing across restarts, set `FILEDROP_SECRET` to a long random string.

## Public base URL

`PUBLIC_BASE_URL` is optional. When omitted, FileDrop builds links from the incoming request host/protocol.

## UI state gallery

`ui-state-gallery.html` is a standalone preview of the modern logo, retro logo and warning/critical/success/info/locked/offline state icons.
