# Audit File List For Master Prompt

This file gives you the exact file batches to paste into your master audit prompt.

Goal:
- keep the audit focused
- avoid overwhelming the model with too much code at once
- review the most security-critical logic first

Recommended audit order:
1. Backend scan pipeline
2. Extension background and runtime detection
3. Popup UI and state flow
4. Dashboard and analytics UI
5. Tests and validation files

Use this workflow:
1. Open `MASTER_AUDIT_PROMPT_COPY_PASTE.md`
2. Paste the full prompt into Claude
3. Paste Batch 1 files
4. Say `START AUDIT - BATCH 1`
5. Repeat for each batch
6. After all batches, ask for:
   `Now give me a consolidated global audit with critical issues, important issues, false positives, UX trust problems, performance risks, and ship readiness.`

---

## Batch 1 - Highest Priority: Backend Core Scan Pipeline

Why this batch matters:
- This is the source of truth for risk scoring
- It determines false positives, false negatives, trust overrides, and final explanations

Paste these files first:

```text
backend/src/index.ts
backend/src/app.ts
backend/src/routes/scan.routes.ts
backend/src/controllers/scan.controller.ts
backend/src/services/scan.service.ts
backend/src/services/decision.service.ts
backend/src/services/scoring.service.ts
backend/src/services/behaviorRisk.service.ts
backend/src/services/pageInteraction.service.ts
backend/src/services/explanation.service.ts
backend/src/services/reputation.service.ts
backend/src/services/safeBrowsing.service.ts
backend/src/services/domainIntelligence.service.ts
backend/src/services/domainEnrichment.service.ts
backend/src/services/threatIntel.service.ts
backend/src/types/scan.types.ts
backend/src/lib/logger.ts
backend/src/lib/env.ts
```

Ask Claude:

```text
Audit Batch 1 only.
Focus on:
- scoring correctness
- trust override correctness
- false positive risk on trusted domains
- false negative risk on phishing or redirect chains
- explanation quality and contradiction risk
- error handling and degraded AI behavior
- rate limiting, caching, and performance concerns
```

---

## Batch 2 - Extension Background And Runtime Detection

Why this batch matters:
- This is where browser events become live threat signals
- It controls runtime updates, per-tab state, and popup/dashboard data flow

Paste these files second:

```text
extension/src/background/index.ts
extension/src/background/storage.ts
extension/src/background/trackerBackground.ts
extension/src/background/vaultWorker.ts
extension/src/content/index.ts
extension/src/content/runtimeMonitor.ts
extension/src/content/interactionDetector.ts
extension/src/content/overlayInjector.ts
extension/src/preclick/linkInterceptor.ts
extension/src/preclick/redirectDecoder.ts
extension/src/preclick/redirectChainExtractor.ts
extension/src/preclick/intentClassifier.ts
extension/src/preclick/riskScorer.ts
extension/src/api/client.ts
extension/src/types/index.ts
extension/src/utils/url.ts
extension/manifest.json
```

Ask Claude:

```text
Audit Batch 2 only.
Focus on:
- runtime signal correctness
- message flow correctness
- race conditions between content scripts and background
- data consistency for SCAN_UPDATED and GET_SCAN_DATA
- performance impact on browsing
- permission risks in manifest
- bypass or allowlist abuse risk
- sensitive data protection flow
```

---

## Batch 3 - Popup UI, State, And User Trust

Why this batch matters:
- This is the user-facing decision surface
- Bad wording or contradictory states will destroy trust even if detection is technically correct

Paste these files third:

```text
extension/src/popup/App.tsx
extension/src/popup/store.ts
extension/src/store/useExtensionStore.ts
extension/src/hooks/useScanResult.ts
extension/src/popup/tabs/ShieldTab.tsx
extension/src/popup/tabs/ReportTab.tsx
extension/src/popup/tabs/SettingsTab.tsx
extension/src/popup/tabs/VaultTab.tsx
extension/src/popup/tabs/UnlockTab.tsx
extension/src/popup/components/ExplanationCard.tsx
extension/src/popup/components/RiskMeter.tsx
extension/src/popup/components/RiskBadge.tsx
extension/src/popup/components/SignalCard.tsx
extension/src/popup/components/ProgressBar.tsx
extension/src/popup/components/ActivityItem.tsx
extension/src/popup/components/ActionBar.tsx
extension/src/popup/components/ReportForm.tsx
extension/src/popup/main.tsx
```

Ask Claude:

```text
Audit Batch 3 only.
Focus on:
- user trust and clarity
- contradiction between safe verdict and scary warning chips
- popup information density
- accessibility and readability
- action safety for bypass, allowlist, and rescan
- state management correctness
- degraded AI fallback UX
- whether the popup feels like a product or a feature pile
```

---

## Batch 4 - Dashboard And Deep Analytics UI

Why this batch matters:
- This is where deep analysis, history, and reporting live
- It should support investigation without duplicating popup clutter

Paste these files fourth:

```text
extension/src/dashboard/App.tsx
extension/src/dashboard/main.tsx
extension/src/dashboard/pages/Overview.tsx
extension/src/dashboard/pages/History.tsx
extension/src/dashboard/pages/Reports.tsx
extension/src/dashboard/pages/Downloads.tsx
extension/src/dashboard/pages/Analytics.tsx
extension/src/dashboard/components/ThreatHistory.tsx
extension/src/dashboard/components/ThreatHistoryList.tsx
extension/src/dashboard/components/CommunityFeed.tsx
extension/src/dashboard/components/MetricCard.tsx
extension/src/dashboard/components/ThreatChart.tsx
extension/src/dashboard/components/StatCard.tsx
extension/src/hooks/useThreatHistory.ts
```

If some filenames differ slightly in your repo, paste the matching dashboard pages/components that exist.

Ask Claude:

```text
Audit Batch 4 only.
Focus on:
- usefulness of dashboard vs popup
- analytics quality
- history accuracy
- reporting workflow quality
- duplication between popup and dashboard
- scalability and maintainability of dashboard structure
```

---

## Batch 5 - Vault And Sensitive Data Protection

Why this batch matters:
- This is security-critical user data logic
- It needs correctness, isolation, and clean UX boundaries

Paste these files fifth:

```text
extension/src/crypto/vault.ts
extension/src/store/useVaultStore.ts
extension/src/popup/components/VaultStatusCard.tsx
extension/src/popup/components/PasswordGenerator.tsx
extension/src/popup/components/UnlockButton.tsx
backend/src/services/report.service.ts
backend/src/routes/report.routes.ts
backend/src/controllers/report.controller.ts
```

If a listed component does not exist, skip it and include the closest vault or password generation component that does.

Ask Claude:

```text
Audit Batch 5 only.
Focus on:
- vault security assumptions
- sensitive data exposure risk
- reporting abuse risk
- clipboard and generated password handling
- unlock/auth flow correctness
```

---

## Batch 6 - Tests, Validation, And Quality Gates

Why this batch matters:
- This reveals whether your security claims are actually backed by tests

Paste these files sixth:

```text
backend/prisma/schema.prisma
extension/package.json
backend/package.json
extension/tsconfig.json
backend/tsconfig.json
extension/src/preclick/__tests__/redirectDecoder.test.ts
extension/src/preclick/__tests__/riskScorer.test.ts
backend/src/**/*.test.ts
backend/src/**/*.spec.ts
extension/src/**/*.test.ts
extension/src/**/*.spec.ts
```

If glob patterns are hard to gather manually, paste the real test files that exist.

Ask Claude:

```text
Audit Batch 6 only.
Focus on:
- missing test coverage
- false positive and false negative validation gaps
- performance regression coverage
- runtime and UI message flow coverage
- whether current tests are enough for a production security product
```

---

## Minimum Fast-Track Audit

If you do not want to paste everything, start with only these files:

```text
backend/src/services/scan.service.ts
backend/src/services/scoring.service.ts
backend/src/services/behaviorRisk.service.ts
backend/src/services/pageInteraction.service.ts
extension/src/background/index.ts
extension/src/content/runtimeMonitor.ts
extension/src/preclick/riskScorer.ts
extension/src/popup/tabs/ShieldTab.tsx
extension/src/popup/components/ExplanationCard.tsx
extension/src/hooks/useScanResult.ts
extension/manifest.json
```

This gives you the highest-signal audit in the shortest time.

---

## Questions To Ask After All Batches

Once Claude has seen all important batches, ask these:

```text
1. What are the top 5 production-blocking issues?
2. Where are the biggest false positive risks?
3. Where are the biggest false negative or bypass risks?
4. Does the trust override system create any dangerous blind spots?
5. Which UI elements reduce user trust or create confusing decisions?
6. What should be fixed before a demo to investors or judges?
7. What should be fixed before a public launch?
8. Give me a prioritized 48-hour fix plan.
```

---

## What Good Audit Output Should Look Like

You want the final audit to include:

- Critical issues
- Important issues
- Nice-to-have improvements
- False positive findings
- False negative findings
- UX trust issues
- Performance risks
- Architecture risks
- Test coverage gaps
- Ship readiness percentage

If the model gives vague feedback, push it with:

```text
Be concrete.
For each issue, include:
- severity
- exact file
- why it matters
- attack or failure scenario
- fix recommendation
```

---

## Practical Recommendation

Best order for your current project state:

1. Batch 1
2. Batch 2
3. Batch 3
4. Consolidated audit
5. Only then review Batch 4 and Batch 5 if you want polish and scale guidance

That gets you to the highest-value product audit fastest.
