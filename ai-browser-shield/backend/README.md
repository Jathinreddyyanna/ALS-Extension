# AI Browser Shield Backend

## 1. Prerequisites

- Node.js 20+
- PostgreSQL
- Redis
- Google Gemini API key

## 2. Quick start

```bash
git clone <your-repo-url>
cd ai-browser-shield/backend
npm install
cp .env.example .env
npx prisma migrate dev
npx prisma db seed
npm run dev
```

## 3. Environment variables table

| Name | Required | Description | Example |
| --- | --- | --- | --- |
| `NODE_ENV` | Yes | Runtime mode | `development` |
| `PORT` | Yes | API port | `3001` |
| `DATABASE_URL` | Yes | Prisma database URL | `postgresql://user:pass@localhost:5432/ai_browser_shield` |
| `DIRECT_URL` | Yes | Direct PostgreSQL URL | `postgresql://user:pass@localhost:5432/ai_browser_shield` |
| `REDIS_URL` | Yes | Redis connection string | `redis://localhost:6379` |
| `GEMINI_API_KEY` | Yes for AI, optional for heuristic-only mode | Gemini API key | `AIza...` |
| `ALLOWED_ORIGINS` | Yes | Comma-separated allowed origins | `chrome-extension://abc,http://localhost:5173` |
| `API_KEY` | Yes | Extension API key | `long_random_string` |
| `ADMIN_KEY` | Yes for admin endpoints | Admin-only API key | `different_long_random_string` |
| `DAILY_SALT_SECRET` | Yes | Secret used to derive rotating IP salts | `32_char_random_string_for_ip_hashing` |
| `GEMINI_MODEL` | Yes | Gemini model name | `gemini-1.5-flash` |
| `GEMINI_TIMEOUT_MS` | Yes | Gemini timeout in milliseconds | `8000` |
| `MAX_URL_LENGTH` | Yes | URL truncation length for AI input | `2048` |
| `ENABLE_FILE_SCAN` | Yes | Toggle file scanning | `true` |
| `SCAN_CACHE_TTL_LOW` | Yes | Low-risk URL cache TTL seconds | `3600` |
| `SCAN_CACHE_TTL_HIGH` | Yes | High-risk URL cache TTL seconds | `300` |

## 4. API reference

### `POST /api/v1/scan/url`
Description: Scan a URL using parser, heuristics, reputation, cache, and Gemini fallback logic.

Example request:
```json
{
  "url": "https://example.com/login",
  "signals": { "popupRisk": 2 },
  "sessionId": "session-1",
  "tabId": 3
}
```

Example response:
```json
{
  "url": "https://example.com/login",
  "domain": "example.com",
  "riskScore": 58,
  "riskLevel": "HIGH",
  "explanation": "Suspicious URL structure detected.",
  "keyIndicators": ["suspiciousKeywords", "redirectParam"],
  "recommendedAction": "warn",
  "confidence": 0.8,
  "category": "phishing",
  "heuristic": 45,
  "dbRiskScore": 20,
  "dbReportCount": 1,
  "cached": false,
  "processedMs": 64,
  "urlType": "standard"
}
```

### `POST /api/v1/scan/file`
Description: Scan a file from JSON metadata or multipart binary upload.

Example request:
```json
{
  "filename": "invoice.pdf",
  "mimeType": "application/pdf",
  "sizeBytes": 10240,
  "sourceUrl": "https://example.com/file.pdf",
  "base64Content": "JVBERi0x..."
}
```

Example response:
```json
{
  "verdict": "SAFE",
  "confidence": 0.91,
  "explanation": "No strong malicious indicators were found.",
  "indicators": [],
  "recommended_action": "allow",
  "fileScanId": "file-uuid",
  "processedMs": 35
}
```

### `GET /api/v1/scan/domain/:domain`
Description: Return `DomainScore`, recent detection events, recent reports, and 7-day trend.

### `POST /api/v1/reports`
Description: Submit a user threat report for a URL.

Example request:
```json
{
  "url": "https://evil.example/phish",
  "category": "phishing",
  "description": "Fake login page"
}
```

Example response:
```json
{
  "id": "report-uuid",
  "status": "pending",
  "message": "Threat report received."
}
```

### `GET /api/v1/reports/recent`
Description: Return the latest 20 confirmed threat reports.

### `POST /api/v1/downloads/approve`
Description: Approve a pending download.

### `POST /api/v1/downloads/cancel`
Description: Cancel a pending download.

### `GET /api/v1/health`
Description: Health check for DB, Redis, Gemini, uptime, version, and env.

### `GET /api/v1/stats`
Description: Return aggregate app stats.

### `POST /api/v1/ai/explain`
Description: Force an AI-backed explanation for popup UI.

### `GET /api/v1/ai/debug`
Description: Admin-only Gemini connectivity debug endpoint.

### `POST /api/v1/security/email`
Description: Extract URLs from an email body, score them, and derive sender risk.

### `POST /api/v1/admin/domains/:domain/confirm`
Description: Admin-only confirm/reject flow for flagged domains.

### `GET /api/v1/admin/domains/flagged`
Description: Admin-only list of unconfirmed domains with risk score >= 50.

## 5. Architecture overview

### URL parser
The parser normalizes, decodes, classifies, and safely handles standard URLs, localhost, private IPs, browser-internal schemes, file/data/blob URLs, credentials-in-URL, IDNs, and very long inputs before anything else runs.

### Heuristic scorer
The scorer computes 15 separate security signals including typosquatting, suspicious TLDs, IP hostnames, homoglyphs, redirect parameters, query abuse, path entropy, and port anomalies, then converts them into a bounded 0-100 risk score.

### AI service
The Gemini layer receives structured scan context, enforces post-processing rules in code, retries once with backoff on transient failures, and degrades to cache or heuristic-only results on timeouts, parse errors, or 429s.

### DB
PostgreSQL stores domain reputation, detection events, reports, file scans, malicious file hashes, rate-limit logs, app stats, and admin actions while preserving IP privacy through rotating salted hashes.

### Cache
Redis is the primary cache for URL scans, domain scores, health, stats, reports, and debug results; an in-memory LRU fallback keeps the service operational if Redis is down.

### Response
Controllers validate outbound payloads through Zod response schemas before sending them so malformed server-side responses are caught and converted into internal schema errors instead of leaking bad data.

## 6. Edge cases handled

1. URL is localhost.
2. URL is private IP.
3. URL is browser internal.
4. URL is file protocol.
5. URL is data URL.
6. URL is blob URL.
7. URL exceeds 2048 characters for AI input.
8. URL includes credentials.
9. IDN and punycode handling.
10. Gemini invalid JSON fallback.
11. Gemini timeout fallback.
12. Gemini 429 fallback.
13. Redis unavailable fallback.
14. DB unavailable degraded scan path.
15. Hostnames without TLD treated as internal.
16. IP plus port with no path.
17. FTP/SFTP/WS/WSS handled safely.
18. Empty URL validation failure.
19. `http://.` validation failure.
20. Extremely nested subdomains.
21. Percent-encoded URLs decoded before scoring.
22. Unicode path normalization.
23. Repeated scan cache hit.
24. Concurrent scan lock to avoid duplicate Gemini calls.
25. DomainScore upsert on first scan.
26. Stale domain decay.
27. File extension and MIME mismatch.
28. Zero-byte file detection.
29. Known malicious file hash match.
30. Localhost download treated safe.
31. Duplicate report deduplication.
32. Report flood rate limiting.
33. Spike auto-flag on many unique IP hashes.
34. Request object stripping on Zod-validated bodies.
35. Admin key disabled response.
36. Missing Gemini key heuristic-only mode.
37. Port already in use error logging.
38. Invalid DB URL startup failure path.
39. Body size limit handler.
40. Malformed JSON handler.
41. CORS preflight handling.
42. 404 route handling.
43. Score clamping to avoid overflow.
44. NaN guard in score calculation.
45. Prisma unique/upsert-safe flows.

## 7. Testing

- Run all tests with:
```bash
npm test
```

- Run coverage with:
```bash
npx vitest run --coverage
```

- Run a single test file with:
```bash
npx vitest run tests/scanService.test.ts
```

## 8. Deployment

- PM2:
```bash
npm run build
pm2 start ecosystem.config.js
```

- Production checklist:
  - Set all required environment variables.
  - Provision PostgreSQL and run Prisma migrations.
  - Provision Redis.
  - Add a real Gemini API key.
  - Use HTTPS and a reverse proxy.
  - Restrict `ALLOWED_ORIGINS` to extension IDs and trusted dev hosts.

- Supabase/Railway notes:
  - Use the provider connection string for `DATABASE_URL`.
  - Set `DIRECT_URL` for migrations if your provider requires a direct connection.
  - Railway and Neon both work with the current Prisma Postgres datasource.

## 9. Troubleshooting

1. `DATABASE_URL` invalid: verify the full PostgreSQL URI and credentials.
2. Redis connection refused: confirm Redis is running or let the service degrade to LRU fallback.
3. Gemini key missing: set `GEMINI_API_KEY` or expect heuristic-only mode.
4. Gemini 404 or unsupported model: verify `GEMINI_MODEL`.
5. Port already in use: change `PORT` or stop the conflicting process.
6. Prisma client out of date: run `npx prisma generate`.
7. Migration errors: verify `DIRECT_URL` and DB permissions.
8. 401 from protected routes: check `x-api-key` or `x-admin-key`.
9. 403 CORS errors: update `ALLOWED_ORIGINS`.
10. 413 payload too large: keep JSON under 10MB and multipart uploads under 50MB.
