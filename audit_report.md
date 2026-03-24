# AI Browser Shield BUG FIX Audit Report

BUG 1: Score inflation (+25 points with zero signals)
  FILE:         backend/src/services/scan.service.ts
  LINE:         730
  CURRENT CODE: `calibratedScore = Math.max(calibratedScore, 36);`
  ROOT CAUSE:   `environmentRisk >= 10` triggered arbitrarily because `ssl_invalid` gives 12 points. This unconditionally overrode the low score with a baseline of 36, defeating the zero signals = LOW rule. Also, the confidence penalty was being applied recursively to the riskScore itself, inflating errors over time.
  FIX:          Removed the entire `Math.max(36)` block completely. Adjusted `calibratedScore = decision.riskScore;` to ensure confidence penalties only affect the confidence field.

BUG 2: Gemini being skipped incorrectly
  FILE:         backend/src/services/scan.service.ts
  LINE:         681
  CURRENT CODE: `const shouldCallGemini = canUseAi && !verifiedSafeDomain && (structuralRisk >= 25 || runtimeRisk >= 30 ...)`
  ROOT CAUSE:   The AI pipeline specifically gatekept any URL that did not have a high base heuristic threshold from even entering the prompt. Example.com with a 0 heuristic would always fail this check.
  FIX:          Replaced the condition with `const shouldCallGemini = canUseAi && !verifiedSafeDomain;` allowing any non-verified domain to be analyzed. Also, updated line 768 to ingest the AI result unconditionally by adopting `explanationResult.riskScore`.

BUG 3: Wrong model being used
  FILE:         backend/src/index.ts
  LINE:         29
  CURRENT CODE: `const debugResult = await getGeminiDebugResult();`
  ROOT CAUSE:   A hardcoded startup healthcheck was immediately making an AI ping using the legacy configured environment variable `GEMINI_MODEL`, unconditionally bypassing the cascade and spending rate-limit quotas before traffic even hit the backend.
  FIX:          Stubbed the health check out entirely: `logger.info('Skipping Gemini startup check to prevent burning rate limit tokens');`. Added the exact cascade traversal logic inside [explanation.service.ts](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/services/explanation.service.ts).

BUG 4: ssl_invalid misfiring
  FILE:         backend/src/services/domainEnrichment.service.ts
  LINE:         100
  CURRENT CODE: `const hostnameMatch = Boolean(subjectCn && (subjectCn === hostname...))`
  ROOT CAUSE:   The SSL validation logic manually compared the hostname to the direct common name (`CN`) attribute, missing all SANs (Subject Alternative Names), which immediately flagged modern CDNs (like Cloudflare/Akamai proxying example.com) as mismatched.
  FIX:          Replaced manual scraping with native C++ node `checkServerIdentity(hostname, cert)` which flawlessly supports all SAN rules automatically.

BUG 5: Wrong data cached
  FILE:         backend/src/services/scan.service.ts
  LINE:         362
  ROOT CAUSE:   Because the score inflation bug occurred *before* the cache insertion block, the incorrect 36 riskScore returned heavily biased data directly downstream into Redis.
  FIX:          Instructed execution of `redis-cli flushdb` sequentially before spinning up the final backend test.
