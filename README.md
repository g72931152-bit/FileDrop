# FileDrop

A strict, minimalist temporary file-sharing site built for a Render Web Service.

## Features

- Drag & drop or browser file selection
- Streaming uploads up to 2 GB per file
- Share URL format: `https://your-domain.example/AbC123`
- Delete after download
- Expire after 1 hour (default)
- Optional password protection
- Download limit from 1 to 5
- Automatic cleanup of expired / exhausted shares
- No account required
- Responsive UI with subtle cold-toned motion and `prefers-reduced-motion` support
- `/healthz` health endpoint for Render

## Run locally

```bash
npm install
npm start
```

Open `http://localhost:10000`.

## Deploy on Render

The included `render.yaml` is configured for a free Node Web Service. You can also create a Web Service manually with:

- Build command: `npm install`
- Start command: `npm start`
- Health check path: `/healthz`

The service binds to `0.0.0.0` and reads the Render `PORT` environment variable.

## Important storage note

This app deliberately writes upload streams to disk instead of buffering entire files in RAM, so the Node process does not need 2 GB of RAM for a 2 GB file.

Render Free Web Services use an ephemeral filesystem. Uploaded files can be lost when the service restarts, redeploys, or spins down. This build is therefore suitable for testing, demos, and short-lived sharing, but not for durable production file hosting on the free plan.

For durable storage, move file bytes to an object-storage provider (or attach a Render Persistent Disk on a paid service) and store share metadata in a persistent datastore.

## Security notes

- Files are always served as downloads with `application/octet-stream` and `X-Content-Type-Options: nosniff`.
- Share IDs are randomly generated and do not expose filesystem paths.
- Passwords are stored as salted scrypt hashes.
- Password unlock uses an HTTP-only, same-site signed cookie.
- Upload and password endpoints have lightweight per-IP rate limiting.
- The server never loads an uploaded file into memory as a whole.
