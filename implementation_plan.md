# Implementation Plan: Fix AI Layer Heuristic Fallback

The AI layer is currently falling back to heuristic analysis even when Gemini is reachable. This plan aims to ensure Gemini consistently returns valid JSON that the backend can parse.

## Proposed Changes

### [Backend]
Summary: Enforce structured JSON output from Gemini and improve parsing robustness.

#### [MODIFY] [ai.service.ts](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/services/ai.service.ts)
- Update [generateContentOnce](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/services/ai.service.ts#127-141) to use `generationConfig: { responseMimeType: 'application/json' }`.
- Update the Gemini prompt to include a strict JSON schema requirement for [AiAssessment](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/types/scan.types.ts#122-137).
- Update [parseJson](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/services/ai.service.ts#34-47) to strip markdown code blocks (e.g., ` ```json ... ``` `) before parsing as a safety measure.

#### [MODIFY] [index.ts](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/src/config/index.ts)
- Update the default `GEMINI_MODEL` to `gemini-1.5-flash` (or `gemini-1.5-flash-latest`). 
> [!NOTE]
> The previous error `models/gemini-1.5-flash is not found for API version v1beta` might be resolved by the latest SDK version (v0.24.1) correctly mapping to `v1` or by using the model name without the `models/` prefix which the SDK handles.

#### [MODIFY] [.env](file:///c:/Users/jathi/Downloads/ai-browser-shield-v2-FINAL/ai-browser-shield/backend/.env)
- Update `GEMINI_MODEL` to `gemini-1.5-flash`.

## Verification Plan

### Automated Tests
- Run the backend in development mode: `npm run dev`
- Call the debug endpoint:
  ```powershell
  $headers = @{ 'x-admin-key' = 'abs-admin-key-xncrzubg-2025' }; Invoke-RestMethod -Method Get -Uri 'http://localhost:3001/api/v1/ai/debug' -Headers $headers | ConvertTo-Json -Depth 8
  ```
- Verify that `sample.source` is `'gemini'` and `aiDegraded` is `false`.

### Manual Verification
- Perform a live URL scan using the extension (after reloading it) or via `curl`:
  ```powershell
  $headers = @{ 'x-api-key' = 'abs-api-key-xncrzubg-2025' }; $body = @{ url = 'https://example.com/login' } | ConvertTo-Json; Invoke-RestMethod -Method Post -Uri 'http://localhost:3001/api/v1/scan/url' -Headers $headers -ContentType 'application/json' -Body $body | ConvertTo-Json -Depth 8
  ```
- Check the backend logs to ensure no `heuristic_parse_fallback` messages appear.
