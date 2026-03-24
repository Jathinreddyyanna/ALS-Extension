import { scoreUrl } from '../detection/urlScorer'
import { checkDownload } from '../detection/downloadChecker'
import { trackRedirect, resetTab, trackNewTab, getNewTabInfo, clearNewTabInfo, NEW_TAB_SPAM_WINDOW, RETURN_REDIRECT_WINDOW } from '../detection/redirectTracker'
import { saveThreatEvent } from './storage'
import { getDomainScore, scanFile, scanUrl } from '../api/client'
import { PopupAndRedirectTracker, type PopupAndRedirectAnalysis } from '../detection/popupRedirectTracker'
import { initTrackerBlocking } from './trackerBackground'
import type {
  ThreatEvent,
  RiskLevel,
  SignalMap,
  UrlScanResult,
  ActivityFeedItem,
  RuntimeSignalSummary,
  RiskHistorySnapshot,
  DomainReputation,
  PatternFlags,
  SensitiveDataRisk,
} from '../types'
import {
  initVaultWorker,
  dispatchVaultCommand,
  handleAutofillRequest,
  handleSaveAccepted,
  setupVaultSessionAlarm,
} from './vaultWorker'
import type { VaultCommand } from '../types/vault'

const pendingDownloads = new Map<number, {
  suggest: (result?: chrome.downloads.DownloadFilenameSuggestion) => void
  item: chrome.downloads.DownloadItem
  tabId: number
}>()
const STATIC_ADBLOCK_RULESET_ID = 'adblock'
const blockedCounts: Record<number, { ads: number; trackers: number; cryptominers: number }> = {}
const siteRiskByTab = new Map<number, {
  url: string
  domain: string
  riskScore: number
  riskLevel: RiskLevel
  explanation: string
  source?: string
}>()

// Canonical popup + redirect tracker per tab (Brave-like behavior)
const popupRedirectTrackers = new Map<number, PopupAndRedirectTracker>()
const lastUrlByTab = new Map<number, string>()
const lastPopupRedirectSnapshotByTab = new Map<
  number,
  { popupCount: number; totalRedirects: number; riskLevel: PopupAndRedirectAnalysis['riskLevel'] }
>()
const EMPTY_SIGNALS: SignalMap = {
  typosquatScore: 0,
  suspiciousTLD: 0,
  ipAsHostname: 0,
  longSubdomains: 0,
  suspiciousKeywords: 0,
  encodedChars: 0,
  pathEntropy: 0,
  portAnomaly: 0,
}
const pageLoadTimes = new Map<number, { url: string; ts: number }>()
const redirectMap = new Map<number, number>()
const domSignalsByTab = new Map<number, Record<string, number>>()
// PHASE 3: keep the latest runtime telemetry per tab for rescans and popup access
const runtimeSignalsByTab = new Map<number, {
  url: string
  runtimeScore: number
  riskLevel: RiskLevel
  signals: Record<string, number>
}>()
// PHASE 4: store the latest merged scan result snapshot per tab for popup/dashboard consumers
const scanResultByTab = new Map<number, UrlScanResult>()
// PHASE 4: keep a lightweight activity feed per tab for the live security dashboard
const activityLogByTab = new Map<number, ActivityFeedItem[]>()
// PHASE 4: track tabs the user explicitly bypassed for the current browser session
const bypassedTabs = new Set<number>()
// PHASE 5: keep recent risk snapshots per tab to detect trend and support richer UI
const riskHistoryByTab = new Map<number, RiskHistorySnapshot[]>()
// PHASE 5: maintain lightweight in-memory domain reputation based on scans and reports
const domainReputationStore = new Map<string, DomainReputation>()
const PHASE4_BYPASS_STORAGE_KEY = 'phase4:bypassedTabs'
const PHASE4_ALLOWLIST_STORAGE_KEY = 'allowlist'
const ADAPTIVE_WEIGHTS = {
  popup: 10,
  redirect: 15,
  hiddenIframe: 25,
  suspiciousForm: 30,
  scriptInjection: 20,
  overlay: 22,
  domMutation: 1,
  passwordField: 16,
  creditCardField: 20,
  earlyUnload: 18,
} as const

function normalizeRuntimeSignals(tabId: number): RuntimeSignalSummary {
  const runtimeSignals = runtimeSignalsByTab.get(tabId)?.signals ?? {}
  const domSignals = domSignalsByTab.get(tabId) ?? {}
  const popupSnapshot = lastPopupRedirectSnapshotByTab.get(tabId)

  return {
    popupCount: Math.max(
      Number(runtimeSignals.popupCount ?? runtimeSignals.popupFrequency ?? 0),
      Number(domSignals.popupCount ?? domSignals.popupFrequency ?? 0),
      popupSnapshot?.popupCount ?? 0
    ),
    redirectCount: Math.max(
      Number(runtimeSignals.redirectCount ?? runtimeSignals.redirectChains ?? 0),
      Number(domSignals.redirectCount ?? domSignals.redirectChains ?? 0),
      popupSnapshot?.totalRedirects ?? 0,
      redirectMap.get(tabId) ?? 0
    ),
    hiddenIframeCount: Math.max(
      Number(runtimeSignals.hiddenIframeCount ?? runtimeSignals.hiddenIframes ?? 0),
      Number(domSignals.hiddenIframeCount ?? domSignals.hiddenIframes ?? 0)
    ),
    overlayCount: Math.max(
      Number(runtimeSignals.overlayCount ?? runtimeSignals.overlayTrap ?? 0),
      Number(domSignals.overlayCount ?? domSignals.overlayTrap ?? 0)
    ),
    scriptInjectionCount: Math.max(
      Number(runtimeSignals.scriptInjectionCount ?? 0),
      Number(domSignals.scriptInjectionCount ?? 0)
    ),
    suspiciousFormCount: Math.max(
      Number(runtimeSignals.suspiciousFormCount ?? 0),
      Number(domSignals.suspiciousFormCount ?? 0)
    ),
    domMutationCount: Math.max(
      Number(runtimeSignals.domMutationCount ?? 0),
      Number(domSignals.domMutationCount ?? 0)
    ),
  }
}

function getActivityLog(tabId: number): ActivityFeedItem[] {
  return activityLogByTab.get(tabId) ?? []
}

function appendActivity(tabId: number, type: string, detail: string) {
  const next: ActivityFeedItem = {
    type,
    timestamp: Date.now(),
    detail,
  }
  const existing = activityLogByTab.get(tabId) ?? []
  activityLogByTab.set(tabId, [next, ...existing].slice(0, 25))
}

function getRiskHistory(tabId: number): RiskHistorySnapshot[] {
  return riskHistoryByTab.get(tabId) ?? []
}

function rememberRiskSnapshot(tabId: number, snapshot: RiskHistorySnapshot) {
  const history = riskHistoryByTab.get(tabId) ?? []
  const last = history[0]
  if (last && last.riskScore === snapshot.riskScore && last.riskLevel === snapshot.riskLevel) {
    const sameSignals =
      last.signals.popupCount === snapshot.signals.popupCount &&
      last.signals.redirectCount === snapshot.signals.redirectCount &&
      last.signals.hiddenIframeCount === snapshot.signals.hiddenIframeCount &&
      last.signals.suspiciousFormCount === snapshot.signals.suspiciousFormCount &&
      last.signals.creditCardFieldCount === snapshot.signals.creditCardFieldCount &&
      last.signals.passwordFieldCount === snapshot.signals.passwordFieldCount
    if (sameSignals) return
  }
  riskHistoryByTab.set(tabId, [snapshot, ...history].slice(0, 20))
}

function getDomainReputation(domain: string): DomainReputation | null {
  return domainReputationStore.get(domain) ?? null
}

function updateDomainReputation(domain: string, riskScore: number, reportDelta = 0) {
  if (!domain) return
  const current = domainReputationStore.get(domain)
  if (!current) {
    domainReputationStore.set(domain, {
      domain,
      reportCount: Math.max(0, reportDelta),
      averageRisk: riskScore,
      lastSeen: Date.now(),
    })
    return
  }

  const sampleWeight = Math.max(1, current.reportCount + 1)
  const blendedAverage = Math.round(((current.averageRisk * sampleWeight) + riskScore) / (sampleWeight + 1))
  domainReputationStore.set(domain, {
    domain,
    reportCount: Math.max(0, current.reportCount + reportDelta),
    averageRisk: blendedAverage,
    lastSeen: Date.now(),
  })
}

function getPatternFlags(signals: RuntimeSignalSummary, history: RiskHistorySnapshot[]): PatternFlags {
  const phishingPattern = signals.popupCount > 2 && signals.hiddenIframeCount > 0 && signals.suspiciousFormCount > 0
  const redirectTrap = signals.redirectCount > 1 && (signals.earlyUnloadCount ?? 0) > 0
  const recent = history.slice(0, 3)
  const increasingRiskTrend =
    recent.length >= 3 &&
    recent[0].riskScore > recent[1].riskScore &&
    recent[1].riskScore > recent[2].riskScore

  return { phishingPattern, redirectTrap, increasingRiskTrend }
}

function getSensitiveDataRisk(
  riskLevel: RiskLevel,
  signals: RuntimeSignalSummary,
  patternFlags: PatternFlags,
  allowlisted = false,
  bypassed = false
): SensitiveDataRisk {
  if (allowlisted || bypassed) {
    return {
      detected: false,
      passwordFields: 0,
      creditCardFields: 0,
      level: 'none',
      message: 'Sensitive input protections are relaxed for this trusted session.',
    }
  }

  const passwordFields = signals.passwordFieldCount ?? 0
  const creditCardFields = signals.creditCardFieldCount ?? 0
  const hasSensitiveFields = passwordFields > 0 || creditCardFields > 0

  if (!hasSensitiveFields) {
    return {
      detected: false,
      passwordFields: 0,
      creditCardFields: 0,
      level: 'none',
      message: 'No sensitive input fields detected on this page.',
    }
  }

  const isDangerous = riskLevel === 'HIGH' || riskLevel === 'CRITICAL' || patternFlags.phishingPattern || patternFlags.redirectTrap

  return {
    detected: isDangerous || riskLevel === 'MEDIUM',
    passwordFields,
    creditCardFields,
    level: isDangerous ? 'high' : 'warning',
    message: isDangerous
      ? 'Sensitive fields detected on a risky page. Avoid entering passwords or payment details.'
      : 'Sensitive fields detected. Double-check the page before submitting personal data.',
  }
}

function computeAdaptiveAdjustments(
  url: string,
  baseScore: number,
  signals: RuntimeSignalSummary,
  reputation: DomainReputation | null,
  history: RiskHistorySnapshot[]
) {
  const contextPath = `${url}`.toLowerCase()
  const isLoginPage = /login|signin|verify|auth|secure|account|checkout|payment|billing/.test(contextPath)
  let boost = 0

  boost += signals.popupCount * ADAPTIVE_WEIGHTS.popup
  boost += signals.redirectCount * ADAPTIVE_WEIGHTS.redirect
  boost += signals.hiddenIframeCount * ADAPTIVE_WEIGHTS.hiddenIframe
  boost += signals.suspiciousFormCount * ADAPTIVE_WEIGHTS.suspiciousForm
  boost += signals.scriptInjectionCount * ADAPTIVE_WEIGHTS.scriptInjection
  boost += signals.overlayCount * ADAPTIVE_WEIGHTS.overlay
  boost += Math.min(15, signals.domMutationCount * ADAPTIVE_WEIGHTS.domMutation)
  boost += (signals.passwordFieldCount ?? 0) * ADAPTIVE_WEIGHTS.passwordField
  boost += (signals.creditCardFieldCount ?? 0) * ADAPTIVE_WEIGHTS.creditCardField
  boost += (signals.earlyUnloadCount ?? 0) * ADAPTIVE_WEIGHTS.earlyUnload

  if (isLoginPage && signals.hiddenIframeCount > 0) {
    boost += 40
  }

  if (signals.popupCount > 2 && signals.hiddenIframeCount > 0 && signals.suspiciousFormCount > 0) {
    boost += 50
  }

  if (signals.redirectCount > 1 && (signals.earlyUnloadCount ?? 0) > 0) {
    boost += 35
  }

  if (reputation?.reportCount && reputation.reportCount >= 10) {
    boost += 20
  }

  if (reputation?.averageRisk && reputation.averageRisk >= 70) {
    boost += 10
  }

  const patternFlags = getPatternFlags(signals, history)
  if (patternFlags.increasingRiskTrend) {
    boost += 12
  }

  const score = Math.min(100, Math.max(baseScore, baseScore + Math.round(boost * 0.25)))
  const riskLevel: RiskLevel =
    score >= 75 ? 'CRITICAL'
      : score >= 50 ? 'HIGH'
        : score >= 30 ? 'MEDIUM'
          : 'LOW'

  return { score, riskLevel, patternFlags }
}

async function getAllowlistDomains(): Promise<string[]> {
  try {
    const result = await chrome.storage.local.get(PHASE4_ALLOWLIST_STORAGE_KEY)
    const allowlist = result[PHASE4_ALLOWLIST_STORAGE_KEY]
    return Array.isArray(allowlist) ? allowlist.filter((item): item is string => typeof item === 'string') : []
  } catch {
    return []
  }
}

function isAllowlistedDomain(hostname: string, allowlist: string[]): boolean {
  return allowlist.some((domain) => hostname === domain || hostname.endsWith(`.${domain}`))
}

async function persistBypassedTabs() {
  try {
    await chrome.storage.session.set({
      [PHASE4_BYPASS_STORAGE_KEY]: Array.from(bypassedTabs),
    })
  } catch {
    // Ignore session persistence failures; in-memory bypass still works.
  }
}

async function loadPhase4SessionState() {
  try {
    const result = await chrome.storage.session.get(PHASE4_BYPASS_STORAGE_KEY)
    const saved = result[PHASE4_BYPASS_STORAGE_KEY]
    if (Array.isArray(saved)) {
      for (const tabId of saved) {
        if (typeof tabId === 'number') {
          bypassedTabs.add(tabId)
        }
      }
    }
  } catch {
    // Session storage is optional; start with an empty bypass set.
  }
}

function toDashboardResult(tabId: number, fallbackUrl = ''): UrlScanResult {
  const stored = scanResultByTab.get(tabId)
  const siteRisk = siteRiskByTab.get(tabId)
  const url = stored?.url || siteRisk?.url || runtimeSignalsByTab.get(tabId)?.url || fallbackUrl
  const domain = stored?.domain || siteRisk?.domain || (() => {
    try {
      return url ? new URL(url).hostname : ''
    } catch {
      return ''
    }
  })()
  const signals = normalizeRuntimeSignals(tabId)
  const modelUsed = stored?.modelUsed || (stored?.aiSource === 'heuristic' || siteRisk?.source === 'heuristic' ? 'heuristic' : 'gemini')
  const aiDegraded = stored?.aiDegraded ?? modelUsed === 'heuristic'
  const aiUsed = stored?.aiUsed ?? !aiDegraded
  const history = getRiskHistory(tabId)
  const reputation = getDomainReputation(domain)
  const patternFlags = stored?.patternFlags ?? getPatternFlags(signals, history)
  const sensitiveDataRisk = stored?.sensitiveDataRisk ?? getSensitiveDataRisk(
    stored?.riskLevel ?? siteRisk?.riskLevel ?? 'LOW',
    signals,
    patternFlags,
    stored?.allowlisted ?? false,
    bypassedTabs.has(tabId)
  )

  return {
    url,
    domain,
    riskScore: stored?.riskScore ?? siteRisk?.riskScore ?? 0,
    riskLevel: stored?.riskLevel ?? siteRisk?.riskLevel ?? 'LOW',
    explanation: stored?.explanation ?? siteRisk?.explanation ?? 'Scan in progress.',
    aiExplanation: stored?.aiExplanation ?? stored?.explanation ?? siteRisk?.explanation ?? '',
    keyIndicators: stored?.keyIndicators ?? [],
    positives: stored?.positives ?? [],
    warnings: stored?.warnings ?? [],
    recommendedAction: stored?.recommendedAction ?? 'warn',
    confidence: stored?.confidence ?? 0,
    category: stored?.category ?? 'unknown',
    categories: stored?.categories ?? [],
    verdict: stored?.verdict,
    heuristic: stored?.heuristic ?? siteRisk?.riskScore ?? 0,
    dbRiskScore: stored?.dbRiskScore ?? 0,
    dbReportCount: stored?.dbReportCount ?? 0,
    cached: stored?.cached ?? false,
    aiDegraded,
    aiSource: stored?.aiSource ?? (aiDegraded ? 'heuristic' : 'gemini'),
    aiUsed,
    modelUsed,
    processedMs: stored?.processedMs ?? 0,
    urlType: stored?.urlType ?? 'website',
    source: stored?.source ?? siteRisk?.source ?? (aiDegraded ? 'heuristic' : 'background'),
    signalsUsed: stored?.signalsUsed ?? [],
    trustSignals: stored?.trustSignals ?? [],
    contentCategory: stored?.contentCategory,
    behaviorRisk: stored?.behaviorRisk,
    runtimeRisk: stored?.runtimeRisk ?? runtimeSignalsByTab.get(tabId)?.runtimeScore ?? 0,
    domRisk: stored?.domRisk ?? Math.min(100, signals.hiddenIframeCount * 20 + signals.overlayCount * 25 + signals.domMutationCount),
    interactionRisk: stored?.interactionRisk ?? Math.min(100, signals.popupCount * 15 + signals.redirectCount * 15 + signals.suspiciousFormCount * 20),
    warningsEnhanced: stored?.warningsEnhanced,
    allowlisted: stored?.allowlisted ?? false,
    reputationStatus: stored?.reputationStatus,
    decisionBasis: stored?.decisionBasis,
    skip: stored?.skip,
    reason: stored?.reason,
    sources: stored?.sources,
    confidenceLevel: stored?.confidenceLevel,
    threatSource: stored?.threatSource,
    analysisDepth: stored?.analysisDepth,
    safeBrowsingMatched: stored?.safeBrowsingMatched,
    safeBrowsingThreatTypes: stored?.safeBrowsingThreatTypes,
    signals,
    activityLog: getActivityLog(tabId),
    modelStatus: aiUsed ? (aiDegraded ? 'degraded' : 'active') : 'offline',
    tabId,
    bypassed: bypassedTabs.has(tabId),
    history,
    reputation,
    patternFlags,
    sensitiveDataRisk,
  }
}

async function emitScanUpdated(tabId: number, fallbackUrl = '') {
  const payload = toDashboardResult(tabId, fallbackUrl)
  try {
    chrome.runtime.sendMessage({ type: 'SCAN_UPDATED', tabId, payload }, () => {
      void chrome.runtime.lastError
    })
  } catch {
    // Popup may be closed; ignore update fan-out failures.
  }
}

async function getTabUrl(tabId: number): Promise<string | null> {
  try {
    const tab = await chrome.tabs.get(tabId)
    return tab?.url ?? null
  } catch {
    return null
  }
}

function getCounterKey(tabId: number) {
  return `counter:${tabId}`
}

async function getTabCounter(tabId: number): Promise<number> {
  try {
    const key = getCounterKey(tabId)
    const result = await chrome.storage.local.get(key)
    const value = result[key]
    return typeof value === 'number' ? value : 0
  } catch {
    return 0
  }
}

async function setTabCounter(tabId: number, count: number) {
  try {
    await chrome.storage.local.set({ [getCounterKey(tabId)]: count })
  } catch {
    // Ignore storage failures; badge updates still attempt to run.
  }
  await safeSetBadge(tabId, '#171B26', count > 0 ? String(count) : '')
}

async function incrementTabCounter(tabId: number) {
  const nextCount = (await getTabCounter(tabId)) + 1
  await setTabCounter(tabId, nextCount)
}

async function resetTabCounter(tabId: number) {
  await setTabCounter(tabId, 0)
}

function getBlockedCategory(ruleId: number): 'ads' | 'trackers' | 'cryptominers' {
  if (ruleId >= 51 && ruleId <= 58) return 'cryptominers'
  if (ruleId >= 59) return 'trackers'
  return 'ads'
}

if (chrome.declarativeNetRequest.onRuleMatchedDebug) {
  chrome.declarativeNetRequest.onRuleMatchedDebug.addListener((info) => {
    const tabId = info.request.tabId
    if (typeof tabId !== 'number' || tabId < 0) return

    if (!blockedCounts[tabId]) {
      blockedCounts[tabId] = { ads: 0, trackers: 0, cryptominers: 0 }
    }

    const category = getBlockedCategory(info.rule.ruleId)
    blockedCounts[tabId][category]++
    chrome.storage.local.set({ [`blocked:${tabId}`]: blockedCounts[tabId] })
    void incrementTabCounter(tabId)
  })
}

async function ensureAdblockRulesetEnabled() {
  try {
    const enabled = await chrome.declarativeNetRequest.getEnabledRulesets()
    if (!enabled.includes(STATIC_ADBLOCK_RULESET_ID)) {
      await chrome.declarativeNetRequest.updateEnabledRulesets({
        enableRulesetIds: [STATIC_ADBLOCK_RULESET_ID],
      })
    }
  } catch (err) {
    console.warn('[Adblock] Failed to verify static ruleset:', err)
  }
}

async function safeSendMessage(tabId: number, message: any) {
  try {
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return
      if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('chrome-extension://') || tab.url.startsWith('devtools://')) return
      chrome.tabs.sendMessage(tabId, message, () => {
        void chrome.runtime.lastError
      })
    })
  } catch {
    // Tab may be closed or not ready; ignore
  }
}

function safeSignals(raw: Partial<SignalMap> | null | undefined): SignalMap {
  const normalized: SignalMap = {
    typosquatScore: raw?.typosquatScore ?? 0,
    suspiciousTLD: raw?.suspiciousTLD ?? 0,
    ipAsHostname: raw?.ipAsHostname ?? 0,
    longSubdomains: raw?.longSubdomains ?? 0,
    suspiciousKeywords: raw?.suspiciousKeywords ?? 0,
    encodedChars: raw?.encodedChars ?? 0,
    pathEntropy: raw?.pathEntropy ?? 0,
    portAnomaly: raw?.portAnomaly ?? 0,
  }

  for (const [key, value] of Object.entries(raw ?? {})) {
    if (typeof value === 'number' && !(key in normalized)) {
      normalized[key] = value
    }
  }

  return normalized
}

async function safeSetBadge(tabId: number, color: string, text: string) {
  try {
    const counter = await getTabCounter(tabId)
    const finalText = counter > 0 ? String(counter) : text
    const finalColor = counter > 0 ? '#171B26' : color
    chrome.tabs.get(tabId, (tab) => {
      if (chrome.runtime.lastError || !tab) return
      chrome.action.setBadgeBackgroundColor({ color: finalColor, tabId }, () => {
        void chrome.runtime.lastError
      })
      chrome.action.setBadgeText({ text: finalText, tabId }, () => {
        void chrome.runtime.lastError
      })
    })
  } catch {
    // Ignore badge updates for tabs that no longer exist.
  }
}

function safeSuggest(
  suggest: (suggestion?: any) => void,
  filename?: string | null
) {
  try {
    if (typeof filename === 'string' && filename.trim().length > 0) {
      suggest({ filename: filename.trim() })
      return
    }
    suggest()
  } catch {
    try {
      suggest()
    } catch {
      // Ignore invalid suggestion failures.
    }
  }
}

function getSiteRiskContext(tabId?: number | null, url?: string) {
  if (typeof tabId === 'number') {
    const existing = siteRiskByTab.get(tabId)
    if (existing) return existing
  }

  if (url) {
    try {
      const hostname = new URL(url).hostname
      for (const value of siteRiskByTab.values()) {
        if (value.domain === hostname) return value
      }
    } catch {
      // ignore invalid URLs
    }
  }

  return null
}

function shouldEscalateFromSiteRisk(siteRisk: { riskLevel: RiskLevel; riskScore: number } | null | undefined) {
  if (!siteRisk) return false
  return siteRisk.riskLevel === 'HIGH' || siteRisk.riskLevel === 'CRITICAL' || siteRisk.riskScore >= 50
}

function getPopupRedirectTracker(tabId: number): PopupAndRedirectTracker {
  let tracker = popupRedirectTrackers.get(tabId)
  if (!tracker) {
    tracker = new PopupAndRedirectTracker()
    popupRedirectTrackers.set(tabId, tracker)
  }
  return tracker
}

function resetPopupRedirectTracker(tabId: number) {
  const tracker = popupRedirectTrackers.get(tabId)
  if (tracker) {
    tracker.reset()
  }
  lastUrlByTab.delete(tabId)
  lastPopupRedirectSnapshotByTab.delete(tabId)
}

function popupRiskSeverity(level: PopupAndRedirectAnalysis['riskLevel']): number {
  switch (level) {
    case 'CRITICAL':
      return 3
    case 'DANGEROUS':
      return 2
    case 'CAUTION':
      return 1
    default:
      return 0
  }
}

async function createThreatEventFromPopupRedirect(
  tabId: number,
  url: string,
  analysis: PopupAndRedirectAnalysis,
  source: 'popup' | 'redirect'
) {
  const prev = lastPopupRedirectSnapshotByTab.get(tabId)
  const hasChange =
    !prev ||
    analysis.popupCount > prev.popupCount ||
    analysis.totalRedirects > prev.totalRedirects ||
    popupRiskSeverity(analysis.riskLevel) > popupRiskSeverity(prev.riskLevel)

  if (!hasChange) return

  lastPopupRedirectSnapshotByTab.set(tabId, {
    popupCount: analysis.popupCount,
    totalRedirects: analysis.totalRedirects,
    riskLevel: analysis.riskLevel,
  })

  let eventType: ThreatEvent['eventType'] = 'popup_abuse'
  if (source === 'redirect' || analysis.totalRedirects > 0) {
    eventType = 'redirect_chain'
  }

  const riskScoreMap: Record<PopupAndRedirectAnalysis['riskLevel'], number> = {
    SAFE: 10,
    CAUTION: 45,
    DANGEROUS: 75,
    CRITICAL: 90,
  }
  const riskScore = riskScoreMap[analysis.riskLevel] ?? 45
  const domain = (() => {
    try {
      return new URL(url).hostname
    } catch {
      return analysis.website || 'unknown'
    }
  })()

  const explanation =
    analysis.flags.join(' | ') ||
    (source === 'redirect'
      ? 'Potentially abusive redirect behavior detected on this site.'
      : 'Excessive popups or overlays detected on this site.')

  await saveThreatEvent({
    id: crypto.randomUUID(),
    eventType,
    domain,
    url,
    riskScore,
    riskLevel:
      analysis.riskLevel === 'CRITICAL'
        ? 'CRITICAL'
        : analysis.riskLevel === 'DANGEROUS'
          ? 'HIGH'
          : analysis.riskLevel === 'CAUTION'
            ? 'MEDIUM'
            : 'LOW',
    aiExplanation: explanation,
    timestamp: Date.now(),
  })
}

function isClearlyJunkRedirect(url: string): boolean {
  try {
    const u = new URL(url)
    const host = u.hostname
    const tld = host.split('.').pop() || ''
    const badTlds = ['top', 'cyou', 'click', 'xyz', 'loan', 'online']
    if (badTlds.includes(tld)) return true
    if (host.length > 40 && /[0-9]/.test(host) && /[a-z]/i.test(host)) return true
    return false
  } catch {
    return false
  }
}

function isSpamPattern(url: string): boolean {
  try {
    const u = new URL(url)
    const host = u.hostname.toLowerCase()
    const full = url.toLowerCase()
    const spamTLDs = ['.xyz', '.tk', '.ml', '.ga', '.cf', '.gq', '.top', '.click', '.loan', '.rest', '.cam', '.icu', '.sbs']
    const spamKeywords = [
      'free-spin', 'you-won', 'winner', 'prize-claim', 'lucky-draw',
      'free-recharge', 'cashback-offer', 'earn-money', 'work-from-home',
      'click-here', 'claim-now', 'limited-offer', 'congratulations',
      'adult', 'xxx', 'casino', 'bet365', 'gambling',
      'download-now', 'install-now', 'update-required', 'virus-detected',
      'your-pc-is-infected', 'call-support', 'tech-support',
    ]

    if (spamTLDs.some((tld) => host.endsWith(tld))) return true
    if (spamKeywords.some((keyword) => full.includes(keyword))) return true
    if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return true
    if (url.length > 300) return true
    if (u.searchParams.has('click_id') && u.searchParams.has('offer_id')) return true
    if (u.searchParams.has('aff_id') || u.searchParams.has('affiliate_id')) return true

    return false
  } catch {
    return false
  }
}

function isLikelySafeTld(hostname: string): boolean {
  const suspiciousTlds = ['xyz', 'tk', 'ml', 'top', 'click', 'loan', 'cam', 'icu', 'sbs']
  const tld = hostname.split('.').pop() ?? ''
  return !suspiciousTlds.includes(tld)
}

function isPostLoginRedirectCandidate(url: string, openerUrl?: string): boolean {
  try {
    const nextUrl = new URL(url)
    const openerHost = openerUrl ? new URL(openerUrl).hostname : ''

    if (openerHost && nextUrl.hostname === openerHost) return true
    if (openerHost && nextUrl.hostname.endsWith(`.${openerHost}`)) return true
    if (openerHost && openerHost.endsWith(`.${nextUrl.hostname}`)) return true

    const safePaths = [
      '/dashboard', '/home', '/account', '/profile', '/welcome', '/feed',
      '/app', '/inbox', '/settings', '/overview', '/callback', '/oauth',
      '/auth/callback', '/login/callback', '/sso', '/saml', '/oidc', '/redirect',
    ]
    if (safePaths.some((path) => nextUrl.pathname.startsWith(path))) return true

    if (nextUrl.protocol === 'https:' && isLikelySafeTld(nextUrl.hostname) && url.length < 200) return true

    return false
  } catch {
    return true
  }
}

const lastAnalyzed = new Map<number, string>()

async function analyzeUrl(tabId: number, url: string, domSignals: Record<string, number> = {}) {
  if (typeof tabId !== 'number' || tabId < 0) return
  if (!url || url.startsWith('chrome://') || url.startsWith('about:') || url.startsWith('chrome-extension://') || url.startsWith('devtools://')) return
  let hostname = ''
  try { hostname = new URL(url).hostname } catch { return }
  if (!hostname) return

  const allowlistDomains = await getAllowlistDomains()

  if (bypassedTabs.has(tabId)) {
    const bypassResult: UrlScanResult = {
      ...toDashboardResult(tabId, url),
      url,
      domain: hostname,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: 'Protection is paused for this tab for the current session.',
      aiExplanation: 'User bypassed protection for this tab. Live telemetry remains visible, but active blocking is paused.',
      keyIndicators: [],
      recommendedAction: 'allow',
      confidence: 1,
      category: 'allowlisted',
      heuristic: 0,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: false,
      aiDegraded: false,
      aiSource: 'heuristic',
      aiUsed: false,
      modelUsed: 'bypass',
      processedMs: 0,
      urlType: 'website',
      source: 'bypass',
      skip: true,
      reason: 'tab_bypassed',
      bypassed: true,
    }
    scanResultByTab.set(tabId, bypassResult)
    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: bypassResult.explanation,
      source: 'bypass',
    })
    appendActivity(tabId, 'bypass_enabled', 'Protection paused for this tab for the current session')
    await safeSetBadge(tabId, '#166534', '')
    await emitScanUpdated(tabId, url)
    return
  }

  if (isAllowlistedDomain(hostname, allowlistDomains)) {
    const allowlistedResult: UrlScanResult = {
      ...toDashboardResult(tabId, url),
      url,
      domain: hostname,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: 'This domain is allowlisted. Standard monitoring remains available without active warnings.',
      aiExplanation: 'Domain matched the extension allowlist. Blocking and warning surfaces are suppressed unless the domain is removed from allowlist.',
      keyIndicators: ['allowlisted'],
      recommendedAction: 'allow',
      confidence: 1,
      category: 'allowlisted',
      heuristic: 0,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: true,
      aiDegraded: false,
      aiSource: 'heuristic',
      aiUsed: false,
      modelUsed: 'allowlist',
      processedMs: 0,
      urlType: 'website',
      source: 'allowlist',
      allowlisted: true,
      skip: true,
      reason: 'extension_allowlist',
      bypassed: false,
    }
    scanResultByTab.set(tabId, allowlistedResult)
    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: 0,
      riskLevel: 'LOW',
      explanation: allowlistedResult.explanation,
      source: 'allowlist',
    })
    appendActivity(tabId, 'allowlisted', `Domain allowlisted: ${hostname}`)
    await safeSetBadge(tabId, '#166534', '')
    await emitScanUpdated(tabId, url)
    return
  }

  if (lastAnalyzed.get(tabId) === url) return
  lastAnalyzed.set(tabId, url)
  lastUrlByTab.set(tabId, url)

  const local = scoreUrl(url)
  const mergedDomSignals = { ...(domSignalsByTab.get(tabId) ?? {}), ...domSignals }
  if (Object.keys(mergedDomSignals).length > 0) {
    domSignalsByTab.set(tabId, mergedDomSignals)
  }
  const signals: SignalMap = {
    ...safeSignals(local?.signals ?? EMPTY_SIGNALS),
    ...mergedDomSignals,
  }
  const runtimeSummary = normalizeRuntimeSignals(tabId)
  const history = getRiskHistory(tabId)
  const reputation = getDomainReputation(hostname)

  const colors: Record<string, string> = { LOW: '#166534', MEDIUM: '#B45309', HIGH: '#DC2626', CRITICAL: '#7F1D1D' }
  try {
    await safeSetBadge(tabId, colors[local.riskLevel] ?? '#166534', local.riskLevel === 'LOW' ? '' : local.score.toString())
  } catch {
    // Ignore badge failures for tabs that disappeared mid-update.
  }

  try {
    const result = await scanUrl(url, signals)
    if (!result) {
      const adaptive = computeAdaptiveAdjustments(url, local.score, runtimeSummary, reputation, history)
      const fallbackResult: UrlScanResult = {
        ...toDashboardResult(tabId, url),
        url,
        domain: hostname,
        riskScore: adaptive.score,
        riskLevel: adaptive.riskLevel,
        explanation: getFallbackExplanation(adaptive.score),
        aiExplanation: '',
        keyIndicators: [],
        positives: [],
        warnings: ['Protection system is in fallback mode'],
        recommendedAction: 'warn',
        confidence: 0,
        category: 'unknown',
        categories: [],
        heuristic: local.score,
        dbRiskScore: 0,
        dbReportCount: 0,
        cached: false,
        aiDegraded: true,
        aiSource: 'heuristic',
        aiUsed: false,
        modelUsed: 'heuristic',
        processedMs: 0,
        urlType: 'website',
        source: 'heuristic',
        patternFlags: adaptive.patternFlags,
      }
      fallbackResult.sensitiveDataRisk = getSensitiveDataRisk(fallbackResult.riskLevel, runtimeSummary, adaptive.patternFlags)
      scanResultByTab.set(tabId, fallbackResult)
      siteRiskByTab.set(tabId, {
        url,
        domain: hostname,
        riskScore: adaptive.score,
        riskLevel: adaptive.riskLevel,
        explanation: getFallbackExplanation(adaptive.score),
        source: 'heuristic',
      })
      updateDomainReputation(hostname, adaptive.score)
      rememberRiskSnapshot(tabId, {
        timestamp: Date.now(),
        riskScore: adaptive.score,
        riskLevel: adaptive.riskLevel,
        signals: runtimeSummary,
      })
      await saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'url_threat',
        domain: hostname,
        url,
        riskScore: adaptive.score,
        riskLevel: adaptive.riskLevel,
        aiExplanation: '',
        source: 'heuristic',
        timestamp: Date.now(),
      })
      appendActivity(tabId, 'heuristic_fallback', 'AI unavailable. Using heuristic mode for this scan')
      appendActivity(tabId, 'scan_completed', `Page scan completed - ${adaptive.riskLevel}`)
      if (fallbackResult.sensitiveDataRisk?.detected) {
        appendActivity(tabId, 'sensitive_data_risk', fallbackResult.sensitiveDataRisk.message)
      }
      if (fallbackResult.sensitiveDataRisk?.detected) {
        try {
          chrome.runtime.sendMessage({ type: 'SENSITIVE_DATA_RISK', tabId, payload: fallbackResult.sensitiveDataRisk }, () => {
            void chrome.runtime.lastError
          })
        } catch {
          // ignore popup broadcast issues
        }
      }
      await emitScanUpdated(tabId, url)
      return
    }

    const baseScore = typeof result.riskScore === 'number' ? result.riskScore : local.score
    const adaptive = computeAdaptiveAdjustments(url, baseScore, runtimeSummary, reputation, history)
    const finalScore = adaptive.score
    const finalRiskLevel = adaptive.riskLevel
    const explanation = result.explanation || getFallbackExplanation(finalScore)
    const recommendedAction = result.recommendedAction ?? 'warn'
    const source = result.aiSource || result.source || 'backend'

    await safeSetBadge(tabId, colors[finalRiskLevel] ?? '#166534', finalRiskLevel === 'LOW' ? '' : String(finalScore))

    scanResultByTab.set(tabId, {
      ...result,
      url,
      domain: hostname,
      riskScore: finalScore,
      riskLevel: finalRiskLevel,
      explanation,
      aiExplanation: result.aiExplanation ?? explanation,
      aiUsed: result.aiUsed ?? source !== 'heuristic',
      aiDegraded: result.aiDegraded ?? source === 'heuristic',
      aiSource: result.aiSource ?? (source === 'heuristic' ? 'heuristic' : 'gemini'),
      modelUsed: result.modelUsed ?? (source === 'heuristic' ? 'heuristic' : 'gemini'),
      category: result.category ?? 'unknown',
      categories: result.categories ?? [],
      keyIndicators: result.keyIndicators ?? [],
      positives: result.positives ?? [],
      warnings: result.warnings ?? [],
      confidence: result.confidence ?? 0,
      heuristic: result.heuristic ?? local.score,
      dbRiskScore: result.dbRiskScore ?? 0,
      dbReportCount: result.dbReportCount ?? 0,
      cached: result.cached ?? false,
      processedMs: result.processedMs ?? 0,
      urlType: result.urlType ?? 'website',
      source,
      patternFlags: adaptive.patternFlags,
      reputation: getDomainReputation(hostname),
      sensitiveDataRisk: getSensitiveDataRisk(finalRiskLevel, runtimeSummary, adaptive.patternFlags, result.allowlisted ?? false, false),
    })
    updateDomainReputation(hostname, finalScore)

    if (finalRiskLevel === 'HIGH' || finalRiskLevel === 'CRITICAL') {
      safeSendMessage(tabId, {
        type: 'SHOW_OVERLAY',
        payload: {
          url,
          score: finalScore,
          riskLevel: finalRiskLevel,
          explanation,
          recommendedAction,
        },
      })
    }

    await saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'url_threat',
      domain: hostname,
      url,
      riskScore: finalScore,
      riskLevel: finalRiskLevel,
      aiExplanation: explanation,
      source,
      timestamp: Date.now(),
    })

    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: finalScore,
      riskLevel: finalRiskLevel,
      explanation,
      source,
    })
    rememberRiskSnapshot(tabId, {
      timestamp: Date.now(),
      riskScore: finalScore,
      riskLevel: finalRiskLevel,
      signals: runtimeSummary,
    })
    appendActivity(tabId, source === 'heuristic' ? 'heuristic_fallback' : 'ai_used', source === 'heuristic' ? 'AI unavailable. Using heuristic mode for this scan' : `AI analysis used (${result.modelUsed || 'gemini'})`)
    appendActivity(tabId, 'scan_completed', `Page scan completed - ${finalRiskLevel}`)
    if (finalRiskLevel === 'LOW') {
      appendActivity(tabId, 'safe', 'No threats detected on this page')
    }
    if (finalRiskLevel === 'HIGH' || finalRiskLevel === 'CRITICAL') {
      appendActivity(tabId, 'blocked', `Elevated risk detected (score: ${finalScore})`)
    }
    const sensitiveRisk = scanResultByTab.get(tabId)?.sensitiveDataRisk
    if (sensitiveRisk?.detected) {
      appendActivity(tabId, 'sensitive_data_risk', sensitiveRisk.message)
      try {
        chrome.runtime.sendMessage({ type: 'SENSITIVE_DATA_RISK', tabId, payload: sensitiveRisk }, () => {
          void chrome.runtime.lastError
        })
      } catch {
        // ignore popup broadcast issues
      }
    }
    await emitScanUpdated(tabId, url)
  } catch {
    const adaptive = computeAdaptiveAdjustments(url, local.score, runtimeSummary, reputation, history)
    const fallbackResult: UrlScanResult = {
      ...toDashboardResult(tabId, url),
      url,
      domain: hostname,
      riskScore: adaptive.score,
      riskLevel: adaptive.riskLevel,
      explanation: getFallbackExplanation(adaptive.score),
      aiExplanation: '',
      keyIndicators: [],
      positives: [],
      warnings: ['Protection system is in fallback mode'],
      recommendedAction: 'warn',
      confidence: 0,
      category: 'unknown',
      categories: [],
      heuristic: local.score,
      dbRiskScore: 0,
      dbReportCount: 0,
      cached: false,
      aiDegraded: true,
      aiSource: 'heuristic',
      aiUsed: false,
      modelUsed: 'heuristic',
      processedMs: 0,
      urlType: 'website',
      source: 'heuristic',
      patternFlags: adaptive.patternFlags,
    }
    fallbackResult.sensitiveDataRisk = getSensitiveDataRisk(fallbackResult.riskLevel, runtimeSummary, adaptive.patternFlags)
    scanResultByTab.set(tabId, fallbackResult)
    siteRiskByTab.set(tabId, {
      url,
      domain: hostname,
      riskScore: adaptive.score,
      riskLevel: adaptive.riskLevel,
      explanation: getFallbackExplanation(adaptive.score),
      source: 'heuristic',
    })
    updateDomainReputation(hostname, adaptive.score)
    rememberRiskSnapshot(tabId, {
      timestamp: Date.now(),
      riskScore: adaptive.score,
      riskLevel: adaptive.riskLevel,
      signals: runtimeSummary,
    })

    await saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'url_threat',
      domain: hostname,
      url,
      riskScore: adaptive.score,
      riskLevel: adaptive.riskLevel,
      aiExplanation: '',
      source: 'heuristic',
      timestamp: Date.now(),
    }).catch(() => {})
    appendActivity(tabId, 'heuristic_fallback', 'AI unavailable. Using heuristic mode for this scan')
    appendActivity(tabId, 'scan_completed', `Page scan completed - ${adaptive.riskLevel}`)
    if (fallbackResult.sensitiveDataRisk?.detected) {
      appendActivity(tabId, 'sensitive_data_risk', fallbackResult.sensitiveDataRisk.message)
    }
    await emitScanUpdated(tabId, url)
  }
}

function getFallbackExplanation(score: number): string {
  if (score >= 80) return 'This website shows multiple high-risk signals. We strongly recommend leaving immediately.'
  if (score >= 60) return 'This website has several suspicious characteristics. Be very cautious with any personal information.'
  return 'This website has unusual patterns. Proceed with caution.'
}

// ── Navigation Listeners ──────────────────────────────────────────────────────
chrome.webNavigation.onBeforeNavigate.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return
  const lastLoad = pageLoadTimes.get(tabId)
  if (lastLoad) {
    const timeSinceLoad = Date.now() - lastLoad.ts
    const isDifferentUrl = lastLoad.url !== url

    if (isDifferentUrl && timeSinceLoad < RETURN_REDIRECT_WINDOW) {
      const { score } = scoreUrl(url)

      if (!(score >= 60 && isSpamPattern(url))) {
        pageLoadTimes.delete(tabId)
        return
      }

      safeSendMessage(tabId, {
        type: 'CLICKJACK_WARNING',
        payload: {
          blockedUrl: url,
          score,
          riskLevel: 'HIGH',
          reason: `This site tried to redirect you to ${(() => { try { return new URL(url).hostname } catch { return url } })()} immediately after loading.`,
        },
      })

      saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'redirect_chain',
        domain: (() => { try { return new URL(url).hostname } catch { return url } })(),
        url,
        riskScore: 75,
        riskLevel: 'HIGH',
        aiExplanation: `Suspicious rapid redirect detected to ${url}`,
        timestamp: Date.now(),
      }).catch(() => {})

      pageLoadTimes.delete(tabId)
      return
    }
    pageLoadTimes.delete(tabId)
  }

  blockedCounts[tabId] = { ads: 0, trackers: 0, cryptominers: 0 }
  chrome.storage.local.set({ [`blocked:${tabId}`]: blockedCounts[tabId] })
  redirectMap.delete(tabId)
  domSignalsByTab.delete(tabId)
  scanResultByTab.delete(tabId)
  activityLogByTab.delete(tabId)
  riskHistoryByTab.delete(tabId)
  void resetTabCounter(tabId)
  resetTab(tabId)
  resetPopupRedirectTracker(tabId)
  analyzeUrl(tabId, url)
})

chrome.webNavigation.onCommitted.addListener(({ tabId, url, frameId, transitionQualifiers }) => {
  if (frameId !== 0) return
  if (transitionQualifiers.includes('server_redirect') || transitionQualifiers.includes('client_redirect')) {
    const redirectCount = (redirectMap.get(tabId) ?? 0) + 1
    redirectMap.set(tabId, redirectCount)
    if (redirectCount >= 2) {
      safeSendMessage(tabId, {
        type: 'REDIRECT_WARNING',
        payload: { count: redirectCount },
      })
    }

    const redirectState = trackRedirect(tabId, url)
    if (redirectState.exceeded) {
      safeSendMessage(tabId, { type: 'REDIRECT_WARNING', payload: { count: redirectState.count, urls: redirectState.urls, url } })
      appendActivity(tabId, 'redirect_detected', `Redirect chain detected (${redirectState.count} hops)`)
    }

    const previousUrl = lastUrlByTab.get(tabId) || url
    const tracker = getPopupRedirectTracker(tabId)
    const { blocked, reason } = tracker.trackRedirect({
      from: previousUrl,
      to: url,
      method: 'header',
      timestamp: Date.now(),
    })
    lastUrlByTab.set(tabId, url)

    if (blocked) {
      const hostname = (() => {
        try {
          return new URL(previousUrl).hostname
        } catch {
          return 'unknown'
        }
      })()
      const analysis = tracker.analyze(hostname)
      void createThreatEventFromPopupRedirect(tabId, previousUrl, analysis, 'redirect')

      const primaryChain = analysis.redirectChains[analysis.redirectChains.length - 1]
      if (primaryChain && (analysis.riskLevel === 'CAUTION' || analysis.riskLevel === 'DANGEROUS')) {
        safeSendMessage(tabId, {
          type: 'REDIRECT_WARNING',
          payload: { count: primaryChain.totalRedirects, urls: primaryChain.chain, url },
        })
        appendActivity(tabId, 'redirect_detected', `Redirect chain detected (${primaryChain.totalRedirects} hops)`)
      }

    }
  }
})

chrome.tabs.onCreated.addListener((tab) => {
  const tabId = tab.id
  if (typeof tabId !== 'number') return

  chrome.tabs.query({ active: true, currentWindow: true }, (activeTabs) => {
    const openerTab = activeTabs[0]
    if (!openerTab?.id || !openerTab.url) return

    try {
      const openerHost = new URL(openerTab.url).hostname
      const safeHosts = ['google.com', 'github.com', 'youtube.com', 'bing.com', 'stackoverflow.com']
      if (safeHosts.some((host) => openerHost.endsWith(host))) return
    } catch {
      return
    }

    trackNewTab(tabId, openerTab.id, tab.pendingUrl || tab.url || '')
  })
})

chrome.webNavigation.onDOMContentLoaded.addListener(({ tabId, url, frameId }) => {
  if (frameId !== 0) return
  if (!url || url.startsWith('chrome://') || url.startsWith('about:')) return
  pageLoadTimes.set(tabId, { url, ts: Date.now() })
})

// Some SPA navigations don't fire onBeforeNavigate; analyze on tab update as a backup.
chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
  if (changeInfo.status === 'loading') {
    const url = changeInfo.url || tab.url
    if (!url) return

    const newTabInfo = getNewTabInfo(tabId)
    if (!newTabInfo) return

    const age = Date.now() - newTabInfo.ts
    if (age > NEW_TAB_SPAM_WINDOW) {
      clearNewTabInfo(tabId)
      return
    }

    const { score, riskLevel } = scoreUrl(url)
    const isSpamUrl = isSpamPattern(url)

    if (score >= 60 || isSpamUrl) {
      const openerTabId = newTabInfo.openerTabId
      safeSendMessage(openerTabId, {
        type: 'CLICKJACK_WARNING',
        payload: {
          blockedUrl: url,
          score,
          riskLevel,
          reason: isSpamUrl
            ? 'This site tried to open a known spam/ad URL in a new tab without your permission.'
            : `This site tried to silently open a suspicious URL (risk score: ${score}/100) in a new tab.`,
        },
      })

      saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'popup_abuse',
        domain: (() => { try { return new URL(url).hostname } catch { return url } })(),
        url,
        riskScore: Math.max(score, 65),
        riskLevel: 'HIGH',
        aiExplanation: `Suspicious new tab detected: ${url}`,
        timestamp: Date.now(),
      }).catch(() => {})
    }

    clearNewTabInfo(tabId)
    return
  }

  if (changeInfo.status === 'complete' && tab.url) {
    analyzeUrl(tabId, tab.url)
  }
})

// ── Zero-Trust Download Intercept (cancel + backend approval) ─────────────────
chrome.downloads.onDeterminingFilename.addListener((item, suggest) => {
  const filename = item?.filename
  if (!filename || filename.trim() === '') {
    safeSuggest(suggest)
    return
  }

  chrome.tabs.query({ active: true, currentWindow: true }, async (tabs) => {
    const tabId = tabs[0]?.id ?? -1
    const localRisk = checkDownload(filename, item.mime ?? '', item.url ?? '')

    pendingDownloads.set(item.id, { suggest, item, tabId })

    let sourceDomain = ''
    let domainRiskScore = 0
    let domainReportCount = 0
    let domainCategories: string[] = []

    try {
      sourceDomain = new URL(item.url ?? '').hostname
      const domainData = sourceDomain ? await getDomainScore(sourceDomain) : null
      if (domainData) {
        domainRiskScore = domainData.riskScore ?? 0
        domainReportCount = domainData.reportCount ?? 0
        domainCategories = domainData.categories ?? []
      }
    } catch {
      sourceDomain = ''
    }

    let aiResult: Awaited<ReturnType<typeof scanFile>> = null
    try {
      const ext = '.' + (filename.split('.').pop()?.toLowerCase() || 'bin')
      aiResult = await scanFile({
        filename,
        extension: ext,
        mimeType: item.mime || 'application/octet-stream',
        sizeBytes: item.fileSize || 0,
        sourceUrl: item.url || '',
        sourceDomain,
        domainRiskScore,
        domainReportCount,
        domainCategories,
      })
    } catch {
      aiResult = null
    }

    const verdict = aiResult?.verdict ?? (localRisk.level === 'high' ? 'MALICIOUS' : localRisk.level === 'medium' ? 'SUSPICIOUS' : 'SAFE')
    const explanation = aiResult?.explanation ?? localRisk.reason
    const recommendedAction = aiResult?.recommendedAction ?? (localRisk.level === 'high' ? 'block' : localRisk.level === 'medium' ? 'warn' : 'allow')
    const confidence = aiResult?.confidence ?? 0.6
    const indicators = aiResult?.indicators?.length ? aiResult.indicators : [localRisk.reason]

    if (verdict === 'SAFE' && domainRiskScore < 30 && localRisk.level === 'safe') {
      const pending = pendingDownloads.get(item.id)
      if (pending) {
        safeSuggest(pending.suggest)
        pendingDownloads.delete(item.id)
      }
      return
    }

    safeSendMessage(tabId, {
      type: 'DOWNLOAD_WARNING',
      payload: {
        filename,
        downloadId: item.id,
        verdict,
        explanation,
        confidence,
        indicators,
        recommendedAction,
        sourceDomain,
        domainRiskScore,
        domainReportCount,
        sourceRisk: aiResult?.sourceRisk ?? (domainRiskScore >= 75 ? 'dangerous' : domainRiskScore >= 30 ? 'suspicious' : 'safe'),
      },
    })

    void saveThreatEvent({
      id: crypto.randomUUID(),
      eventType: 'download_intercept',
      domain: sourceDomain || (() => { try { return new URL(item.url ?? '').hostname } catch { return 'unknown' } })(),
      url: item.url ?? '',
      riskScore: verdict === 'MALICIOUS' ? 90 : verdict === 'SUSPICIOUS' ? 55 : 20,
      riskLevel: verdict === 'MALICIOUS' ? 'CRITICAL' : verdict === 'SUSPICIOUS' ? 'HIGH' : 'LOW',
      aiExplanation: explanation,
      timestamp: Date.now(),
    })
  })

  return true
})

chrome.downloads.onChanged.addListener((delta) => {
  if (delta.state?.current === 'interrupted' || delta.state?.current === 'complete') {
    pendingDownloads.delete(delta.id)
  }
})

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (!message || typeof message !== 'object') {
    return false
  }

  const senderDomain = (() => { try { return new URL(sender.url || '').hostname } catch { return 'unknown' } })()

  // Popup abuse reported by content script
  if (message.type === 'POPUP_ATTEMPT') {
    const tabId = sender.tab?.id
    if (tabId == null) {
      return false
    }

    void incrementTabCounter(tabId)

    const tracker = getPopupRedirectTracker(tabId)
    const kind = (message.payload?.kind as 'window' | 'iframe' | 'overlay' | 'meta-refresh' | undefined) || 'window'
    const popupUrl =
      (message.payload?.popupUrl as string | undefined) ||
      (message.payload?.url as string | undefined) ||
      sender.url ||
      ''
    const pageUrl = sender.url || popupUrl
    const now = Date.now()

    if (kind === 'iframe' || kind === 'overlay') {
      tracker.trackIframeInjection({
        url: pageUrl,
        iframeUrl: popupUrl,
        timestamp: now,
        isHidden: !!message.payload?.isHidden,
      })
      appendActivity(tabId, kind === 'overlay' ? 'overlay_detected' : 'iframe_hidden', kind === 'overlay' ? 'Fullscreen overlay detected' : 'Hidden iframe injected')
    } else {
      tracker.trackPopupWindow({
        url: pageUrl,
        popupUrl,
        timestamp: now,
      })
      appendActivity(tabId, 'popup_intercepted', 'Popup attempt intercepted')
    }

    const analysis = tracker.analyze(senderDomain)
    void createThreatEventFromPopupRedirect(tabId, pageUrl, analysis, 'popup')

    // Force an immediate re-scan so the UI updates with the new popup signals
    lastAnalyzed.delete(tabId)
    void analyzeUrl(tabId, pageUrl)

    sendResponse?.({
      popupCount: analysis.popupCount,
      popupThreshold: analysis.popupThreshold,
      riskLevel: analysis.riskLevel,
    })
    return false
  }

  if (message.type === 'DOM_SIGNALS_COLLECTED') {
    const tabId = sender.tab?.id
    if (typeof tabId !== 'number') {
      return false
    }

    const payload = message.payload
    const domSignals = Object.fromEntries(
      Object.entries((payload && typeof payload === 'object' ? payload : {}) as Record<string, unknown>)
        .filter(([, value]) => typeof value === 'number')
        .map(([key, value]) => [key, value as number])
    )

    if (Object.keys(domSignals).length === 0) {
      return false
    }

    domSignalsByTab.set(tabId, {
      ...(domSignalsByTab.get(tabId) ?? {}),
      ...domSignals,
    })

    if ((domSignals.hiddenIframes ?? 0) > 0) {
      appendActivity(tabId, 'iframe_hidden', `Hidden iframe injected (${domSignals.hiddenIframes})`)
    }
    if ((domSignals.overlayTrap ?? 0) > 0) {
      appendActivity(tabId, 'overlay_detected', 'Fullscreen overlay detected')
    }
    if ((domSignals.suspiciousFormCount ?? 0) > 0) {
      appendActivity(tabId, 'form_suspicious', `Suspicious form detected (${domSignals.suspiciousFormCount})`)
    }

    const hasHighRisk = (domSignals.overlayTrap ?? 0) > 0 ||
      (domSignals.hiddenIframes ?? 0) > 2 ||
      (domSignals.suspiciousFormCount ?? 0) > 0

    if (hasHighRisk) {
      const currentUrl = lastUrlByTab.get(tabId)
      if (currentUrl) {
        lastAnalyzed.delete(tabId)
        void analyzeUrl(tabId, currentUrl, domSignals)
      }
    }
    void emitScanUpdated(tabId, sender.url ?? '')
    return false
  }

  // PHASE 3: merge live runtime telemetry into the tab risk context and trigger rescans
  if (message.type === 'RUNTIME_SIGNALS_UPDATE') {
    const tabId = sender.tab?.id
    if (typeof tabId !== 'number') {
      return false
    }

    const previousRuntime = runtimeSignalsByTab.get(tabId)?.signals ?? {}

    const payload = message.payload && typeof message.payload === 'object'
      ? message.payload as {
          url?: string
          runtimeScore?: number
          riskLevel?: string
          signals?: Record<string, unknown>
        }
      : {}

    const rawSignals = payload.signals && typeof payload.signals === 'object'
      ? payload.signals
      : {}

    const runtimeSignals = Object.fromEntries(
      Object.entries(rawSignals).filter(([, value]) => typeof value === 'number')
    ) as Record<string, number>

    const runtimeRiskLevel =
      payload.riskLevel === 'CRITICAL' || payload.riskLevel === 'HIGH' || payload.riskLevel === 'MEDIUM'
        ? payload.riskLevel
        : 'LOW'

    runtimeSignalsByTab.set(tabId, {
      url: typeof payload.url === 'string' ? payload.url : sender.url ?? '',
      runtimeScore: typeof payload.runtimeScore === 'number' ? payload.runtimeScore : 0,
      riskLevel: runtimeRiskLevel,
      signals: runtimeSignals,
    })

    if (Object.keys(runtimeSignals).length > 0) {
      domSignalsByTab.set(tabId, {
        ...(domSignalsByTab.get(tabId) ?? {}),
        ...runtimeSignals,
      })
    }

    if ((runtimeSignals.popupCount ?? 0) > Number(previousRuntime.popupCount ?? 0)) {
      appendActivity(tabId, 'popup_intercepted', 'Popup attempt intercepted')
    }
    if ((runtimeSignals.redirectCount ?? runtimeSignals.redirectChains ?? 0) > Number(previousRuntime.redirectCount ?? previousRuntime.redirectChains ?? 0)) {
      appendActivity(tabId, 'redirect_detected', `Redirect chain detected (${runtimeSignals.redirectCount ?? runtimeSignals.redirectChains ?? 0} hops)`)
    }
    if ((runtimeSignals.hiddenIframeCount ?? runtimeSignals.hiddenIframes ?? 0) > Number(previousRuntime.hiddenIframeCount ?? previousRuntime.hiddenIframes ?? 0)) {
      appendActivity(tabId, 'iframe_hidden', 'Hidden iframe injected')
    }
    if ((runtimeSignals.overlayCount ?? runtimeSignals.overlayTrap ?? 0) > Number(previousRuntime.overlayCount ?? previousRuntime.overlayTrap ?? 0)) {
      appendActivity(tabId, 'overlay_detected', 'Fullscreen overlay detected')
    }
    if ((runtimeSignals.scriptInjectionCount ?? 0) > Number(previousRuntime.scriptInjectionCount ?? 0)) {
      appendActivity(tabId, 'script_injected', 'External script injected')
    }
    if ((runtimeSignals.suspiciousFormCount ?? 0) > Number(previousRuntime.suspiciousFormCount ?? 0)) {
      appendActivity(tabId, 'form_suspicious', 'Suspicious form detected')
    }

    if (runtimeRiskLevel === 'HIGH') {
      void safeSetBadge(tabId, '#D97706', '!')
    } else if (runtimeRiskLevel === 'CRITICAL') {
      void safeSetBadge(tabId, '#DC2626', '!!')
    }

    if (runtimeRiskLevel === 'HIGH' || runtimeRiskLevel === 'CRITICAL') {
      const currentUrl =
        (typeof payload.url === 'string' && payload.url) ||
        lastUrlByTab.get(tabId) ||
        sender.url

      if (currentUrl) {
        lastAnalyzed.delete(tabId)
        void analyzeUrl(tabId, currentUrl, runtimeSignals)
      }
    }

    void emitScanUpdated(tabId, typeof payload.url === 'string' ? payload.url : sender.url ?? '')

    return false
  }

  if (message.type === 'PRECLICK_RISK_EVALUATED') {
    const payload = message.payload ?? {}
    const href = typeof payload.href === 'string' ? payload.href : sender.url ?? ''
    const finalUrl = typeof payload.finalUrl === 'string' ? payload.finalUrl : href
    const score = typeof payload.score === 'number' ? payload.score : 0
    const riskLevel = typeof payload.riskLevel === 'string' ? payload.riskLevel : 'LOW'
    const reasons = Array.isArray((payload as { reasons?: unknown[] }).reasons)
      ? ((payload as { reasons?: unknown[] }).reasons ?? []).filter((value): value is string => typeof value === 'string')
      : []

    if (score >= 6) {
      void saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'redirect_chain',
        domain: (() => { try { return new URL(finalUrl).hostname } catch { return senderDomain } })(),
        url: finalUrl,
        riskScore: Math.min(100, Math.round(score * 10)),
        riskLevel: riskLevel === 'CRITICAL' ? 'CRITICAL' : riskLevel === 'HIGH' ? 'HIGH' : 'MEDIUM',
        aiExplanation: `Pre-click warning: ${reasons.join(' | ') || 'High-risk navigation intent detected.'}`,
        source: 'preclick',
        timestamp: Date.now(),
      }).catch(() => {})
    }
    return false
  }

  if (message.type === 'PRECLICK_NAVIGATION_DECISION') {
    const payload = message.payload ?? {}
    const proceeded = Boolean((payload as { proceeded?: boolean }).proceeded)
    const finalUrl = typeof (payload as { finalUrl?: string }).finalUrl === 'string'
      ? (payload as { finalUrl: string }).finalUrl
      : sender.url ?? ''
    const score = typeof (payload as { score?: number }).score === 'number'
      ? (payload as { score: number }).score
      : 0

    if (!proceeded && score >= 6) {
      void saveThreatEvent({
        id: crypto.randomUUID(),
        eventType: 'popup_abuse',
        domain: (() => { try { return new URL(finalUrl).hostname } catch { return senderDomain } })(),
        url: finalUrl,
        riskScore: Math.min(100, Math.round(score * 10)),
        riskLevel: score >= 8 ? 'CRITICAL' : 'HIGH',
        aiExplanation: 'User declined a high-risk navigation after pre-click warning.',
        source: 'preclick',
        timestamp: Date.now(),
      }).catch(() => {})
    }
    return false
  }

  if (message.type === 'BLOCKED_ITEM') {
    const tabId = sender.tab?.id
    if (tabId == null) return false
    void incrementTabCounter(tabId)
    return false
  }

  if (message.type === 'FORM_SUBMITTED') {
    const tabId = sender.tab?.id
    if (typeof tabId === 'number') {
      pageLoadTimes.delete(tabId)
      lastAnalyzed.delete(tabId)
      redirectMap.delete(tabId)
    }
    return false
  }

  // Report button in overlay -> open popup to report tab
  // overlayInjector sends this directly to background (not via content/index.ts relay)
  if (message.type === 'OPEN_REPORT_FORM') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?tab=report' })
    return false
  }

  // PHASE 3: open the extension popup UI in a dedicated tab from runtime warnings
  if (message.type === 'OPEN_POPUP') {
    chrome.tabs.create({ url: chrome.runtime.getURL('popup.html') + '?tab=shield' })
    return false
  }

  if (message.type === 'ALLOW_DOWNLOAD') {
    const downloadId = message.payload?.downloadId
    if (typeof downloadId !== 'number') return false
    const pending = pendingDownloads.get(downloadId)
    if (!pending) return false

    safeSuggest(pending.suggest)
    pendingDownloads.delete(downloadId)
    return false
  }

  if (message.type === 'CANCEL_DOWNLOAD') {
    const downloadId = message.payload?.downloadId
    if (typeof downloadId !== 'number') return false
    const pending = pendingDownloads.get(downloadId)
    if (pending) {
      safeSuggest(pending.suggest)
      chrome.downloads.cancel(downloadId, () => {
        void chrome.runtime.lastError
      })
      pendingDownloads.delete(downloadId)
    } else {
      chrome.downloads.cancel(downloadId, () => {
        void chrome.runtime.lastError
      })
    }
    return false
  }

  if (message.type === 'GET_BLOCKED_COUNTS') {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      const tabId = tabs[0]?.id ?? -1
      sendResponse(blockedCounts[tabId] ?? { ads: 0, trackers: 0, cryptominers: 0 })
    })
    return true
  }

  // PHASE 4: return the latest merged scan snapshot for the requested tab
  if (message.type === 'GET_SCAN_DATA') {
    const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id
    if (typeof tabId !== 'number' || tabId < 0) {
      sendResponse?.(null)
      return false
    }

    void (async () => {
      const existing = scanResultByTab.get(tabId)
      if (!existing) {
        const tabUrl = await getTabUrl(tabId)
        if (tabUrl) {
          lastAnalyzed.delete(tabId)
          await analyzeUrl(tabId, tabUrl, domSignalsByTab.get(tabId) ?? {})
        }
      }
      sendResponse?.(toDashboardResult(tabId))
    })()

    return true
  }

  // PHASE 4: pause active protection for the current tab for this browser session
  if (message.type === 'BYPASS_FOR_TAB') {
    const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id
    if (typeof tabId !== 'number' || tabId < 0) {
      sendResponse?.({ ok: false })
      return false
    }

    bypassedTabs.add(tabId)
    void persistBypassedTabs()
    appendActivity(tabId, 'bypass_enabled', 'Protection paused for this tab for the current session')
    lastAnalyzed.delete(tabId)
    void (async () => {
      const tabUrl = await getTabUrl(tabId)
      if (tabUrl) {
        await analyzeUrl(tabId, tabUrl, domSignalsByTab.get(tabId) ?? {})
      } else {
        await emitScanUpdated(tabId)
      }
      sendResponse?.({ ok: true })
    })()
    return true
  }

  // PHASE 4: persist a domain allowlist entry in extension storage and refresh the tab snapshot
  if (message.type === 'ALLOWLIST_DOMAIN') {
    const rawDomain = typeof message.domain === 'string' ? message.domain : (() => {
      try {
        return new URL(message.url || sender.url || '').hostname
      } catch {
        return ''
      }
    })()

    if (!rawDomain) {
      sendResponse?.({ ok: false })
      return false
    }

    void (async () => {
      const allowlist = await getAllowlistDomains()
      if (!allowlist.includes(rawDomain)) {
        await chrome.storage.local.set({
          [PHASE4_ALLOWLIST_STORAGE_KEY]: [...allowlist, rawDomain].sort(),
        })
      }

      const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id
      if (typeof tabId === 'number' && tabId >= 0) {
        appendActivity(tabId, 'allowlisted', `Domain allowlisted: ${rawDomain}`)
        lastAnalyzed.delete(tabId)
        const tabUrl = await getTabUrl(tabId)
        if (tabUrl) {
          await analyzeUrl(tabId, tabUrl, domSignalsByTab.get(tabId) ?? {})
        } else {
          await emitScanUpdated(tabId)
        }
      }

      sendResponse?.({ ok: true, domain: rawDomain })
    })()

    return true
  }

  // PHASE 4: force a fresh scan for the current tab and fan out the updated result
  if (message.type === 'RESCAN_TAB') {
    const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id
    if (typeof tabId !== 'number' || tabId < 0) {
      sendResponse?.({ ok: false })
      return false
    }

    void (async () => {
      const tabUrl = await getTabUrl(tabId)
      if (!tabUrl) {
        sendResponse?.({ ok: false })
        return
      }

      try {
        const hostname = new URL(tabUrl).hostname
        await chrome.storage.local.remove(`score:${hostname}`)
      } catch {
        // Ignore URL parsing failures; the live rescan still runs.
      }

      scanResultByTab.delete(tabId)
      lastAnalyzed.delete(tabId)
      appendActivity(tabId, 'rescan_requested', 'Manual rescan requested')
      await analyzeUrl(tabId, tabUrl, domSignalsByTab.get(tabId) ?? {})
      sendResponse?.({ ok: true })
    })()

    return true
  }

  // PHASE 5: record user reports into the local reputation store and refresh the live snapshot
  if (message.type === 'REPORT_SITE') {
    const url = typeof message.url === 'string' ? message.url : sender.url ?? ''
    const domain = typeof message.domain === 'string'
      ? message.domain
      : (() => {
          try {
            return new URL(url).hostname
          } catch {
            return ''
          }
        })()
    const riskScore = typeof message.riskScore === 'number' ? message.riskScore : 80
    const tabId = typeof message.tabId === 'number' ? message.tabId : sender.tab?.id

    if (!domain) {
      sendResponse?.({ ok: false })
      return false
    }

    updateDomainReputation(domain, riskScore, 1)

    if (typeof tabId === 'number' && tabId >= 0) {
      appendActivity(tabId, 'report_submitted', `Domain reported by user (${domain})`)
      void emitScanUpdated(tabId, url)
    }

    sendResponse?.({ ok: true, reputation: getDomainReputation(domain) })
    return false
  }

  if (message.type === 'REPORT_BACK_REDIRECT') {
    const { fromUrl, toUrl, tabId: msgTabId } = message.payload ?? {}
    if (fromUrl && toUrl) {
      safeSendMessage(msgTabId ?? (sender.tab?.id ?? -1), {
        type: 'CLICKJACK_WARNING',
        payload: {
          blockedUrl: toUrl,
          score: 70,
          riskLevel: 'HIGH',
          reason: `This site tried to redirect you away from ${(() => { try { return new URL(fromUrl).hostname } catch { return fromUrl } })()} without your permission.`,
        },
      })
    }
    return true
  }

  const VAULT_COMMANDS = new Set([
    'VAULT_CREATE', 'VAULT_UNLOCK', 'VAULT_LOCK', 'VAULT_GET_STATE',
    'VAULT_ADD_ENTRY', 'VAULT_UPDATE_ENTRY', 'VAULT_DELETE_ENTRY',
    'VAULT_MARK_USED', 'VAULT_GET_AUDIT', 'VAULT_SEARCH',
    'VAULT_EXPORT', 'VAULT_IMPORT',
  ])

  if (typeof message.type === 'string' && VAULT_COMMANDS.has(message.type)) {
    void dispatchVaultCommand(message as VaultCommand).then((response) => {
      try {
        sendResponse?.(response)
      } catch {
        // Popup may already be closed.
      }
    })
    return true
  }

  if (message.type === 'VAULT_AUTOFILL_REQUEST') {
    const tabId = sender.tab?.id ?? message.payload?.tabId
    if (!tabId) return false

    const result = handleAutofillRequest({ ...message.payload, tabId })

    if (result.allowed && result.username && result.password) {
      chrome.tabs.sendMessage(tabId, {
        type: 'VAULT_DO_AUTOFILL',
        payload: {
          username: result.username,
          password: result.password,
          usernameSelector: message.payload.usernameSelector,
          passwordSelector: message.payload.passwordSelector,
        },
      }, () => void chrome.runtime.lastError)
    } else {
      chrome.tabs.sendMessage(tabId, {
        type: 'VAULT_AUTOFILL_BLOCKED',
        payload: {
          score: result.trustResult.score,
          reasons: result.trustResult.reasons,
          storedDomain: result.trustResult.matchedEntry?.domain ?? message.payload.domain,
        },
      }, () => void chrome.runtime.lastError)
    }
    return false
  }

  if (message.type === 'VAULT_SAVE_ACCEPTED') {
    void handleSaveAccepted(message.payload)
    return false
  }

  return false
})

// ── Tab Cleanup ───────────────────────────────────────────────────────────────
chrome.tabs.onRemoved.addListener((tabId) => {
  resetTab(tabId)
  resetPopupRedirectTracker(tabId)
  pageLoadTimes.delete(tabId)
  redirectMap.delete(tabId)
  siteRiskByTab.delete(tabId)
  domSignalsByTab.delete(tabId)
  runtimeSignalsByTab.delete(tabId)
  scanResultByTab.delete(tabId)
  activityLogByTab.delete(tabId)
  riskHistoryByTab.delete(tabId)
  bypassedTabs.delete(tabId)
  delete blockedCounts[tabId]
  chrome.storage.local.remove(`blocked:${tabId}`)
  chrome.storage.local.remove(getCounterKey(tabId))
  void persistBypassedTabs()
})

void ensureAdblockRulesetEnabled()
void loadPhase4SessionState()
initTrackerBlocking()
void initVaultWorker()
setupVaultSessionAlarm()
