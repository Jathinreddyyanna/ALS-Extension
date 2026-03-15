import React, { useCallback, useEffect, useState } from 'react'
import {
  type TabStats,
  type SessionStats,
  type TrackerCategory,
  getSessionStats,
  resetSessionStats,
  formatBytes,
} from '../../detection/trackerEngine'

interface TrackerShieldProps {
  tabId?: number | null
}

interface LiveStats {
  tab: TabStats | null
  session: SessionStats
}

const CATEGORY_META: Record<TrackerCategory, {
  label: string
  sublabel: string
  icon: string
  color: string
  bg: string
  border: string
}> = {
  ad: {
    label: 'Ads',
    sublabel: 'Ad networks and display ads',
    icon: 'Ad',
    color: '#F87171',
    bg: 'rgba(239,68,68,0.08)',
    border: 'rgba(239,68,68,0.2)',
  },
  tracker: {
    label: 'Trackers',
    sublabel: 'Analytics and user profiling',
    icon: 'Tr',
    color: '#FB923C',
    bg: 'rgba(249,115,22,0.08)',
    border: 'rgba(249,115,22,0.2)',
  },
  fingerprinter: {
    label: 'Fingerprinters',
    sublabel: 'Device identity scripts',
    icon: 'Fp',
    color: '#C084FC',
    bg: 'rgba(192,132,252,0.08)',
    border: 'rgba(192,132,252,0.2)',
  },
  social: {
    label: 'Social Trackers',
    sublabel: 'Cross-site social widgets',
    icon: 'So',
    color: '#60A5FA',
    bg: 'rgba(96,165,250,0.08)',
    border: 'rgba(96,165,250,0.2)',
  },
  cryptominer: {
    label: 'Cryptominers',
    sublabel: 'CPU hijacking scripts',
    icon: 'Cm',
    color: '#FBBF24',
    bg: 'rgba(251,191,36,0.08)',
    border: 'rgba(251,191,36,0.2)',
  },
  bounce_tracker: {
    label: 'Bounce Trackers',
    sublabel: 'Redirect-based tracking',
    icon: 'Bt',
    color: '#34D399',
    bg: 'rgba(52,211,153,0.08)',
    border: 'rgba(52,211,153,0.2)',
  },
}

function AnimatedNumber({ value, duration = 600 }: { value: number; duration?: number }) {
  const [display, setDisplay] = useState(value)
  const [prev, setPrev] = useState(value)

  useEffect(() => {
    if (value === prev) return

    const start = Date.now()
    const from = prev
    const to = value

    const step = () => {
      const elapsed = Date.now() - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setDisplay(Math.round(from + (to - from) * eased))
      if (progress < 1) {
        requestAnimationFrame(step)
      } else {
        setPrev(to)
      }
    }

    requestAnimationFrame(step)
  }, [duration, prev, value])

  return <span>{display.toLocaleString()}</span>
}

function ShieldRing({ total, max = 100 }: { total: number; max?: number }) {
  const radius = 44
  const circumference = 2 * Math.PI * radius
  const fill = Math.min(total / Math.max(max, 1), 1)
  const dash = circumference * fill
  const color =
    total === 0 ? '#22C55E'
    : total < 20 ? '#60A5FA'
    : total < 50 ? '#FB923C'
    : '#F87171'

  return (
    <svg width="108" height="108" viewBox="0 0 108 108">
      <circle cx="54" cy="54" r={radius + 8} fill="none" stroke={color} strokeWidth="1" opacity="0.15" />
      <circle cx="54" cy="54" r={radius} fill="none" stroke="#1E293B" strokeWidth="8" />
      <circle
        cx="54"
        cy="54"
        r={radius}
        fill="none"
        stroke={color}
        strokeWidth="8"
        strokeDasharray={`${dash} ${circumference}`}
        strokeDashoffset={circumference * 0.25}
        strokeLinecap="round"
        style={{ transition: 'stroke-dasharray 0.6s cubic-bezier(0.34,1.56,0.64,1), stroke 0.4s ease' }}
      />
      <text x="54" y="48" textAnchor="middle" fontSize="18" fill="#93C5FD" dominantBaseline="middle">TS</text>
      <text x="54" y="68" textAnchor="middle" fontSize="11" fill={color} fontWeight="800">
        {total > 999 ? `${(total / 1000).toFixed(1)}k` : total}
      </text>
      <text x="54" y="79" textAnchor="middle" fontSize="8" fill="#475569" letterSpacing="0.5">
        BLOCKED
      </text>
    </svg>
  )
}

function CategoryRow({
  category,
  count,
  sessionCount,
  animate,
}: {
  category: TrackerCategory
  count: number
  sessionCount: number
  animate: boolean
}) {
  const meta = CATEGORY_META[category]
  const pct = Math.min((count / Math.max(count + 5, 20)) * 100, 100)

  if (count === 0 && sessionCount === 0) return null

  return (
    <div style={{
      background: count > 0 ? meta.bg : 'transparent',
      border: `1px solid ${count > 0 ? meta.border : '#0F172A'}`,
      borderRadius: '10px',
      padding: '10px 12px',
      transition: 'all 0.3s ease',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '6px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <span style={{
            fontSize: '10px',
            fontWeight: 800,
            color: meta.color,
            minWidth: '22px',
            textTransform: 'uppercase',
          }}>
            {meta.icon}
          </span>
          <div>
            <div style={{ color: '#CBD5E1', fontSize: '12px', fontWeight: 700, lineHeight: 1.2 }}>
              {meta.label}
            </div>
            <div style={{ color: '#334155', fontSize: '10px', marginTop: '1px' }}>
              {meta.sublabel}
            </div>
          </div>
        </div>
        <div style={{ textAlign: 'right' }}>
          <div style={{ color: meta.color, fontSize: '18px', fontWeight: 800, lineHeight: 1 }}>
            {animate ? <AnimatedNumber value={count} /> : count}
          </div>
          {sessionCount > 0 && (
            <div style={{ color: '#334155', fontSize: '9px', marginTop: '1px' }}>
              {sessionCount.toLocaleString()} total
            </div>
          )}
        </div>
      </div>
      {count > 0 && (
        <div style={{ height: '3px', background: '#0F172A', borderRadius: '100px', overflow: 'hidden' }}>
          <div style={{
            height: '100%',
            width: `${pct}%`,
            background: `linear-gradient(90deg, ${meta.color}88, ${meta.color})`,
            borderRadius: '100px',
            transition: 'width 0.6s cubic-bezier(0.34,1.56,0.64,1)',
          }} />
        </div>
      )}
    </div>
  )
}

function BandwidthPill({ bytes }: { bytes: number }) {
  return (
    <div style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '5px',
      background: 'rgba(34,197,94,0.08)',
      border: '1px solid rgba(34,197,94,0.2)',
      borderRadius: '100px',
      padding: '4px 10px',
    }}>
      <span style={{ color: '#4ADE80', fontSize: '11px', fontWeight: 700 }}>
        {formatBytes(bytes)} saved
      </span>
    </div>
  )
}

function ShieldStatus({ total }: { total: number }) {
  if (total === 0) {
    return (
      <div style={{
        display: 'inline-flex',
        alignItems: 'center',
        gap: '5px',
        background: 'rgba(34,197,94,0.1)',
        border: '1px solid rgba(34,197,94,0.25)',
        borderRadius: '100px',
        padding: '3px 10px',
      }}>
        <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#22C55E' }} />
        <span style={{ color: '#22C55E', fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px' }}>
          PAGE CLEAN
        </span>
      </div>
    )
  }

  const label = total < 5 ? 'FEW BLOCKED' : total < 20 ? 'TRACKING ACTIVE' : 'HEAVY TRACKING'
  const color = total < 5 ? '#60A5FA' : total < 20 ? '#FB923C' : '#F87171'
  const bg = total < 5 ? 'rgba(96,165,250,0.1)' : total < 20 ? 'rgba(249,115,22,0.1)' : 'rgba(239,68,68,0.1)'
  const border = total < 5 ? 'rgba(96,165,250,0.25)' : total < 20 ? 'rgba(249,115,22,0.25)' : 'rgba(239,68,68,0.25)'

  return (
    <div style={{
      display: 'inline-flex',
      alignItems: 'center',
      gap: '5px',
      background: bg,
      border: `1px solid ${border}`,
      borderRadius: '100px',
      padding: '3px 10px',
    }}>
      <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: color }} />
      <span style={{ color, fontSize: '10px', fontWeight: 700, letterSpacing: '0.5px' }}>
        {label}
      </span>
    </div>
  )
}

export function TrackerShield({ tabId }: TrackerShieldProps) {
  const [stats, setStats] = useState<LiveStats>({
    tab: null,
    session: {
      totalBlocked: 0,
      ads: 0,
      trackers: 0,
      fingerprinters: 0,
      social: 0,
      cryptominers: 0,
      bounceTrackers: 0,
      bandwidthSavedBytes: 0,
      sitesProtected: 0,
      since: Date.now(),
    },
  })
  const [view, setView] = useState<'page' | 'session'>('page')
  const [animate, setAnimate] = useState(false)
  const [resetting, setResetting] = useState(false)

  const load = useCallback(async () => {
    const session = await getSessionStats()
    let tab = null

    if (typeof tabId === 'number' && tabId >= 0) {
      try {
        tab = await new Promise<TabStats | null>((resolve) => {
          chrome.runtime.sendMessage({ type: 'GET_TAB_TRACKER_STATS', payload: { tabId } }, (res) => {
            if (chrome.runtime.lastError) {
              resolve(null)
              return
            }
            resolve(res?.stats ?? null)
          })
        })
      } catch {
        tab = null
      }
    }

    setStats({ tab, session })
    setAnimate(true)
  }, [tabId])

  useEffect(() => {
    void load()
    const id = window.setInterval(() => {
      void load()
    }, 2000)
    return () => window.clearInterval(id)
  }, [load])

  const handleReset = async () => {
    setResetting(true)
    await resetSessionStats()
    await load()
    window.setTimeout(() => setResetting(false), 800)
  }

  const pageStats = stats.tab
  const sess = stats.session

  const displayAds = view === 'page' ? (pageStats?.ads ?? 0) : sess.ads
  const displayTrackers = view === 'page' ? (pageStats?.trackers ?? 0) : sess.trackers
  const displayFingerprint = view === 'page' ? (pageStats?.fingerprinters ?? 0) : sess.fingerprinters
  const displaySocial = view === 'page' ? (pageStats?.social ?? 0) : sess.social
  const displayCrypto = view === 'page' ? (pageStats?.cryptominers ?? 0) : sess.cryptominers
  const displayBounce = view === 'page' ? (pageStats?.bounceTrackers ?? 0) : sess.bounceTrackers
  const displayTotal = view === 'page' ? (pageStats?.total ?? 0) : sess.totalBlocked
  const displayBandwidth = view === 'page' ? (pageStats?.bandwidthSavedBytes ?? 0) : sess.bandwidthSavedBytes

  return (
    <div style={{
      background: '#080C14',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
      color: '#F1F5F9',
      minHeight: '100%',
    }}>
      <div style={{
        background: 'linear-gradient(135deg, #0D1421 0%, #0A1020 100%)',
        borderBottom: '1px solid #0F172A',
        padding: '16px 18px 14px',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '12px' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div style={{
              width: '36px',
              height: '36px',
              background: 'linear-gradient(135deg, #1E3A8A, #1D4ED8)',
              borderRadius: '10px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '12px',
              fontWeight: 800,
              boxShadow: '0 4px 12px rgba(29,78,216,0.35)',
            }}>
              TS
            </div>
            <div>
              <div style={{ color: '#F1F5F9', fontSize: '14px', fontWeight: 800 }}>
                Tracker Shield
              </div>
              <div style={{ color: '#334155', fontSize: '10px', marginTop: '1px' }}>
                {pageStats?.tabDomain || 'No page active'}
              </div>
            </div>
          </div>
          <ShieldStatus total={displayTotal} />
        </div>

        <div style={{
          display: 'flex',
          background: '#0A0F1A',
          borderRadius: '8px',
          padding: '2px',
          gap: '2px',
        }}>
          {(['page', 'session'] as const).map((nextView) => (
            <button
              key={nextView}
              onClick={() => setView(nextView)}
              style={{
                flex: 1,
                padding: '6px',
                border: 'none',
                cursor: 'pointer',
                borderRadius: '6px',
                background: view === nextView ? '#1E3A8A' : 'transparent',
                color: view === nextView ? '#93C5FD' : '#475569',
                fontSize: '11px',
                fontWeight: 700,
                textTransform: 'uppercase',
                letterSpacing: '0.5px',
                transition: 'all 0.18s ease',
              }}
            >
              {nextView === 'page' ? 'This Page' : 'Session'}
            </button>
          ))}
        </div>
      </div>

      <div style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '20px 20px 12px',
      }}>
        <ShieldRing total={displayTotal} max={Math.max(displayTotal * 1.4, 50)} />

        <div style={{ flex: 1, paddingLeft: '20px' }}>
          <div style={{ marginBottom: '8px' }}>
            <div style={{
              color: '#475569',
              fontSize: '10px',
              fontWeight: 600,
              textTransform: 'uppercase',
              letterSpacing: '1px',
              marginBottom: '3px',
            }}>
              {view === 'page' ? 'Blocked on this page' : 'Blocked this session'}
            </div>
            <div style={{ color: '#F1F5F9', fontSize: '36px', fontWeight: 800, lineHeight: 1, letterSpacing: '-1px' }}>
              {animate ? <AnimatedNumber value={displayTotal} duration={700} /> : displayTotal}
            </div>
          </div>

          <BandwidthPill bytes={displayBandwidth} />

          {view === 'session' && (
            <div style={{ marginTop: '8px', color: '#334155', fontSize: '10px' }}>
              Since {new Date(sess.since).toLocaleDateString()}
            </div>
          )}
        </div>
      </div>

      <div style={{ padding: '0 14px 16px', display: 'flex', flexDirection: 'column', gap: '6px' }}>
        <div style={{
          color: '#334155',
          fontSize: '10px',
          fontWeight: 600,
          textTransform: 'uppercase',
          letterSpacing: '1px',
          marginBottom: '4px',
          paddingLeft: '2px',
        }}>
          Breakdown
        </div>

        {displayTotal === 0 ? (
          <div style={{
            background: '#0A0F1A',
            border: '1px solid #0F172A',
            borderRadius: '12px',
            padding: '24px 16px',
            textAlign: 'center',
          }}>
            <div style={{ color: '#22C55E', fontSize: '13px', fontWeight: 700 }}>
              Nothing blocked yet
            </div>
            <div style={{ color: '#334155', fontSize: '11px', marginTop: '4px' }}>
              {view === 'page' ? 'This page has no trackers or ads' : 'Navigate to sites to see tracking in action'}
            </div>
          </div>
        ) : (
          <>
            <CategoryRow category="ad" count={displayAds} sessionCount={sess.ads} animate={animate} />
            <CategoryRow category="tracker" count={displayTrackers} sessionCount={sess.trackers} animate={animate} />
            <CategoryRow category="fingerprinter" count={displayFingerprint} sessionCount={sess.fingerprinters} animate={animate} />
            <CategoryRow category="social" count={displaySocial} sessionCount={sess.social} animate={animate} />
            <CategoryRow category="cryptominer" count={displayCrypto} sessionCount={sess.cryptominers} animate={animate} />
            <CategoryRow category="bounce_tracker" count={displayBounce} sessionCount={sess.bounceTrackers} animate={animate} />
          </>
        )}
      </div>

      {view === 'session' && (
        <>
          <div style={{
            margin: '0 14px 14px',
            background: '#0A0F1A',
            border: '1px solid #0F172A',
            borderRadius: '10px',
            padding: '12px 14px',
          }}>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              {[
                { label: 'Total Blocked', value: sess.totalBlocked.toLocaleString() },
                { label: 'Data Saved', value: formatBytes(sess.bandwidthSavedBytes) },
                { label: 'Ads', value: sess.ads.toLocaleString() },
                { label: 'Trackers', value: sess.trackers.toLocaleString() },
              ].map(({ label, value }) => (
                <div key={label} style={{ textAlign: 'center' }}>
                  <div style={{ color: '#F1F5F9', fontSize: '14px', fontWeight: 800 }}>{value}</div>
                  <div style={{ color: '#334155', fontSize: '9px', textTransform: 'uppercase', letterSpacing: '0.5px' }}>
                    {label}
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ padding: '0 14px 16px' }}>
            <button
              onClick={handleReset}
              disabled={resetting}
              style={{
                width: '100%',
                padding: '9px',
                background: resetting ? 'rgba(239,68,68,0.05)' : 'rgba(239,68,68,0.08)',
                border: '1px solid rgba(239,68,68,0.2)',
                borderRadius: '8px',
                cursor: resetting ? 'not-allowed' : 'pointer',
                color: '#FCA5A5',
                fontSize: '11px',
                fontWeight: 700,
                letterSpacing: '0.5px',
                transition: 'all 0.15s ease',
              }}
            >
              {resetting ? 'Reset' : 'Reset Session Stats'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}
