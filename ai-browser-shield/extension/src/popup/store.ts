import { create } from 'zustand'
import type { ThreatEvent, CommunityReport, EmailAnalysis, PageContextSnapshot } from '../types'
import { getRecentFeed, submitReport, getDomainScore, scanUrl } from '../api/client'
import { scoreUrl } from '../detection/urlScorer'
import { assessPageContext, hasSensitiveContent } from '../detection/pageScorer'

async function readHistory(): Promise<ThreatEvent[]> {
  return new Promise(resolve => {
    chrome.storage.local.get('threatHistory', (r) => resolve(r.threatHistory || []))
  })
}

async function wipeHistory(): Promise<void> {
  return new Promise(resolve => chrome.storage.local.remove('threatHistory', resolve))
}

interface StoreState {
  history: ThreatEvent[]
  feed: CommunityReport[]
  emailAnalysis: EmailAnalysis | null
  currentScore: number | null
  currentDomain: string
  currentExplanation: string
  activeTab: 'score' | 'history' | 'feed' | 'report' | 'mail'
  isLoading: boolean
  reportSuccess: boolean
  loadAll: () => Promise<void>
  setTab: (tab: StoreState['activeTab']) => void
  submitUserReport: (data: { category: string; description: string }) => Promise<void>
  clearAll: () => Promise<void>
}

export const useStore = create<StoreState>((set, get) => ({
  history: [],
  feed: [],
  emailAnalysis: null,
  currentScore: null,
  currentDomain: '',
  currentExplanation: '',
  activeTab: 'score',
  isLoading: false,
  reportSuccess: false,

  loadAll: async () => {
    set({ isLoading: true })
    let domain = ''
    let currentScore: number | null = null
    let liveExplanation = ''
    try {
      const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
      const url = tabs[0]?.url || ''
      domain = new URL(url).hostname
      const { score: heuristicScore, signals } = scoreUrl(url)
      const pageContext: PageContextSnapshot | null = tabs[0]?.id
        ? await chrome.tabs.sendMessage(tabs[0].id, { type: 'GET_PAGE_CONTEXT' }).catch(() => null)
        : null
      const pageAssessment = (() => {
        try {
          return assessPageContext(new URL(url), pageContext)
        } catch {
          return { score: 0, explanation: '' }
        }
      })()
      const pageScore = pageAssessment.score
      const cached: { score: number; ts: number } | null = await new Promise(resolve => {
        chrome.storage.local.get('score:' + domain, r => resolve(r['score:' + domain] || null))
      })
      if (cached && Date.now() - cached.ts < 600000) {
        currentScore = cached.score
      } else {
        const scoreData = await getDomainScore(domain)
        currentScore = scoreData?.riskScore ?? null
      }
      currentScore = Math.max(currentScore ?? 0, heuristicScore, pageScore)

      const shouldRunLiveScan =
        pageScore >= 20 ||
        heuristicScore >= 30 ||
        (!!pageContext && hasSensitiveContent(pageContext))

      if (shouldRunLiveScan) {
        const liveResult = await scanUrl(
          url,
          pageScore > 0 ? { ...signals, pageContextRisk: pageScore } : signals,
          pageContext
        )
        if (liveResult) {
          liveExplanation = liveResult.explanation || pageAssessment.explanation
          const aiMappedScore =
            liveResult.riskLevel === 'CRITICAL' ? 90 :
            liveResult.riskLevel === 'HIGH' ? 70 :
            liveResult.riskLevel === 'MEDIUM' ? 40 : 10

          currentScore = Math.max(currentScore ?? 0, aiMappedScore, pageScore, heuristicScore)
        }
      }
    } catch {}
    const [history, feed, emailAnalysis] = await Promise.all([
      readHistory(),
      getRecentFeed(),
      new Promise<EmailAnalysis | null>(resolve => chrome.storage.local.get('latestEmailAnalysis', r => resolve(r.latestEmailAnalysis || null)))
    ])
    const domainHistoryScore = history
      .filter(event => event.domain === domain)
      .reduce((max, event) => Math.max(max, event.riskScore || 0), 0)
    currentScore = Math.max(currentScore ?? 0, domainHistoryScore)
    const currentExplanation =
      history.find(event => event.domain === domain && !!event.aiExplanation)?.aiExplanation ||
      liveExplanation
    set({ history, feed, emailAnalysis, currentDomain: domain, currentScore, currentExplanation, isLoading: false })
  },

  setTab: (tab) => set({ activeTab: tab }),

  submitUserReport: async ({ category, description }) => {
    const tabs = await chrome.tabs.query({ active: true, currentWindow: true })
    const url = tabs[0]?.url || ''
    const result = await submitReport({ url, category: category as any, description })
    if (!result) return

    const [history, feed] = await Promise.all([readHistory(), getRecentFeed()])
    set({ history, feed, reportSuccess: true })
    setTimeout(() => set({ reportSuccess: false, activeTab: 'history' }), 2000)
  },

  clearAll: async () => {
    await wipeHistory()
    set({ history: [] })
  },
}))
