import React, { useEffect, useMemo, useState } from 'react'

interface Props {
  score: number | null
  domain: string
  isLoading?: boolean
  reportCount?: number
  onReport?: () => void
  bullets?: string[]
  trustBullets?: string[]
}

type RiskTone = 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' | 'UNKNOWN'

function getRiskTone(score: number | null): RiskTone {
  if (score === null) return 'UNKNOWN'
  if (score >= 75) return 'CRITICAL'
  if (score >= 50) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

const TONE = {
  LOW: { color: '#00AA00', bg: '#052e16', label: 'Safe' },
  MEDIUM: { color: '#FFAA00', bg: '#3f2b00', label: 'Caution' },
  HIGH: { color: '#FF6600', bg: '#431407', label: 'Danger' },
  CRITICAL: { color: '#CC0000', bg: '#450A0A', label: 'Blocked' },
  UNKNOWN: { color: '#64748B', bg: '#0f172a', label: 'Scanning' },
} as const

export function TrustScore({ score, domain, isLoading, reportCount = 0, onReport, bullets = [], trustBullets = [] }: Props) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const [liveScore, setLiveScore] = useState<number | null>(score)
  const [liveBullets, setLiveBullets] = useState<string[]>(bullets)

  useEffect(() => {
    setLiveScore(score)
  }, [score])

  useEffect(() => {
    setLiveBullets(bullets)
  }, [bullets])

  useEffect(() => {
    const listener = (message: { type?: string; payload?: { newScore?: number; reason?: string; reasons?: string[] } }) => {
      if (message.type !== 'SCORE_UPDATED') return
      const nextScore = typeof message.payload?.newScore === 'number' ? message.payload.newScore : null
      if (nextScore !== null) {
        setLiveScore(nextScore)
      }
      if (Array.isArray(message.payload?.reasons) && message.payload.reasons.length > 0) {
        setLiveBullets(message.payload.reasons.slice(0, 5))
      } else if (message.payload?.reason) {
        setLiveBullets((current) => {
          if (current.includes(message.payload!.reason!)) return current
          return [message.payload!.reason!, ...current].slice(0, 5)
        })
      }
    }

    chrome.runtime.onMessage.addListener(listener)
    return () => chrome.runtime.onMessage.removeListener(listener)
  }, [])

  useEffect(() => {
    if (liveScore === null) {
      setAnimatedScore(0)
      return
    }

    const start = performance.now()
    const from = animatedScore
    const to = liveScore
    const duration = 700

    const animate = (now: number) => {
      const progress = Math.min((now - start) / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setAnimatedScore(Math.round(from + (to - from) * eased))
      if (progress < 1) {
        requestAnimationFrame(animate)
      }
    }

    requestAnimationFrame(animate)
  }, [liveScore])

  const riskTone = getRiskTone(liveScore)
  const tone = TONE[riskTone]
  const radius = 56
  const circumference = 2 * Math.PI * radius
  const offset = circumference - ((animatedScore || 0) / 100) * circumference

  const whyBullets = useMemo(() => {
    const merged = [...liveBullets, ...trustBullets.filter((item) => !liveBullets.includes(item))]
    return merged.slice(0, 5)
  }, [liveBullets, trustBullets])

  if (isLoading) {
    return (
      <div style={{ padding: '24px', color: '#94A3B8', textAlign: 'center' }}>
        Analysing live risk…
      </div>
    )
  }

  return (
    <div style={{ padding: '20px', color: '#F8FAFC' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: '16px' }}>
        <div style={{ position: 'relative', width: '138px', height: '138px', flexShrink: 0 }}>
          <svg width="138" height="138" viewBox="0 0 138 138" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="69" cy="69" r={radius} fill="none" stroke="rgba(148,163,184,0.18)" strokeWidth="12" />
            <circle
              cx="69"
              cy="69"
              r={radius}
              fill="none"
              stroke={tone.color}
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dashoffset 0.4s ease, stroke 0.4s ease' }}
            />
          </svg>
          <div style={{ position: 'absolute', inset: 0, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ fontSize: '32px', fontWeight: 800, letterSpacing: '-0.04em' }}>{animatedScore}</div>
            <div style={{ fontSize: '11px', color: '#94A3B8' }}>/ 100</div>
          </div>
        </div>

        <div style={{ minWidth: 0, flex: 1 }}>
          <div style={{ fontSize: '11px', textTransform: 'uppercase', letterSpacing: '0.14em', color: '#94A3B8' }}>
            Current site
          </div>
          <div style={{ marginTop: '6px', fontSize: '15px', fontWeight: 700, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {domain || 'No active tab'}
          </div>
          <div style={{
            marginTop: '10px',
            display: 'inline-flex',
            alignItems: 'center',
            gap: '8px',
            padding: '6px 10px',
            borderRadius: '999px',
            background: tone.bg,
            color: tone.color,
            fontSize: '12px',
            fontWeight: 700,
          }}>
            <span style={{ width: '8px', height: '8px', borderRadius: '999px', background: '#22C55E', boxShadow: '0 0 0 6px rgba(34,197,94,0.15)', animation: 'pulse 1.4s infinite' }} />
            Live Monitoring Active
          </div>
          {reportCount > 0 ? (
            <div style={{ marginTop: '10px', fontSize: '11px', color: '#F59E0B' }}>
              {reportCount} community report{reportCount === 1 ? '' : 's'}
            </div>
          ) : null}
        </div>
      </div>

      <div style={{ marginTop: '18px', borderTop: '1px solid rgba(148,163,184,0.14)', paddingTop: '14px' }}>
        <div style={{ fontSize: '12px', fontWeight: 700, color: '#E2E8F0', marginBottom: '10px' }}>
          Why this score?
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          {whyBullets.length > 0 ? whyBullets.map((bullet) => (
            <div key={bullet} style={{ display: 'flex', gap: '8px', fontSize: '12px', color: '#CBD5E1' }}>
              <span style={{ color: bullet.startsWith('No ') || bullet.startsWith('Official') || bullet.startsWith('Trusted') || bullet.startsWith('HTTPS') ? '#22C55E' : tone.color }}>
                {bullet.startsWith('No ') || bullet.startsWith('Official') || bullet.startsWith('Trusted') || bullet.startsWith('HTTPS') ? '✓' : '⚠'}
              </span>
              <span>{bullet}</span>
            </div>
          )) : (
            <div style={{ fontSize: '12px', color: '#94A3B8' }}>No live threats detected yet.</div>
          )}
        </div>
      </div>

      {onReport ? (
        <button
          type="button"
          onClick={onReport}
          style={{
            marginTop: '16px',
            width: '100%',
            borderRadius: '12px',
            border: '1px solid rgba(148,163,184,0.18)',
            background: 'transparent',
            color: '#CBD5E1',
            padding: '11px 14px',
            fontSize: '12px',
            fontWeight: 700,
            cursor: 'pointer',
          }}
        >
          Report This Site
        </button>
      ) : null}
    </div>
  )
}
