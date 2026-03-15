import { describe, it, expect, vi, beforeEach } from 'vitest'
import { useStore } from './store'

vi.mock('../api/client', () => ({
  getRecentFeed: vi.fn().mockResolvedValue([]),
  submitReport: vi.fn().mockResolvedValue(undefined),
}))

vi.mock('../detection/urlScorer', () => ({
  scoreUrl: vi.fn().mockReturnValue({ score: 42 }),
}))

declare const chrome: any

beforeEach(() => {
  ;(globalThis as any).chrome = {
    tabs: {
      query: vi.fn().mockResolvedValue([{ url: 'https://example.com/' }]),
    },
    storage: {
      local: {
        get: vi.fn((key: string, cb: (result: any) => void) =>
          cb({ threatHistory: [] }),
        ),
        remove: vi.fn((_key: string, cb: () => void) => cb()),
      },
    },
  }
})

describe('popup store', () => {
  it('loads current score using heuristic when no history exists', async () => {
    const { loadAll } = useStore.getState()
    await loadAll()

    const state = useStore.getState()
    expect(state.currentDomain).toBe('example.com')
    expect(state.currentScore).toBe(42)
    expect(state.currentSource).toBe('heuristic')
  })

  it('sets reportSuccess after submitUserReport', async () => {
    const { submitUserReport } = useStore.getState()
    await submitUserReport({ category: 'phishing', description: 'Looks bad' })

    const state = useStore.getState()
    expect(state.reportSuccess).toBe(true)
  })
})

