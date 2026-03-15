import React, { useEffect } from 'react'
import { useStore } from './store'
import { TrustScore } from './components/TrustScore'
import { ThreatHistory } from './components/ThreatHistory'
import { CommunityFeed } from './components/CommunityFeed'
import { ReportForm } from './components/ReportForm'

type Tab = 'score' | 'history' | 'feed' | 'report'

const TABS: { id: Tab; icon: string; label: string }[] = [
  { id: 'score', icon: '🛡️', label: 'Shield' },
  { id: 'history', icon: '🕐', label: 'History' },
  { id: 'feed', icon: '🌐', label: 'Feed' },
  { id: 'report', icon: '🚩', label: 'Report' },
]

const RISK_CONFIG: Record<string, { bg: string; headerBg: string; accent: string; label: string }> = {
  CRITICAL: { bg: '#1A0A0A', headerBg: 'linear-gradient(135deg, #2D0A0A 0%, #1A0505 100%)', accent: '#FF1744', label: 'DANGER' },
  HIGH: { bg: '#150A00', headerBg: 'linear-gradient(135deg, #2A1200 0%, #180A00 100%)', accent: '#FF6B00', label: 'WARNING' },
  MEDIUM: { bg: '#0F0C00', headerBg: 'linear-gradient(135deg, #1E1600 0%, #120E00 100%)', accent: '#FFB300', label: 'CAUTION' },
  LOW: { bg: '#060B14', headerBg: 'linear-gradient(135deg, #0D1524 0%, #060B14 100%)', accent: '#00C851', label: 'SAFE' },
  UNKNOWN: { bg: '#060B14', headerBg: 'linear-gradient(135deg, #0D1524 0%, #060B14 100%)', accent: '#8899BB', label: 'SCANNING' },
}

function getRiskKey(score: number | null): string {
  if (score === null) return 'UNKNOWN'
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

export default function App() {
  const {
    history,
    feed,
    currentScore,
    currentDomain,
    reportCount,
    blockedCounts,
    activeTab,
    isLoading,
    reportSuccess,
    loadAll,
    setTab,
    submitUserReport,
    clearAll,
  } = useStore()

  useEffect(() => {
    void loadAll()
    const params = new URLSearchParams(window.location.search)
    if (params.get('tab') === 'report') setTab('report')
  }, [loadAll, setTab])

  const riskKey = getRiskKey(currentScore)
  const risk = RISK_CONFIG[riskKey]
  const todayThreats = history.filter((e) => Date.now() - e.timestamp < 86400000).length
  const totalBlocked = (blockedCounts.ads || 0) + (blockedCounts.trackers || 0)

  return (
    <div
      style={{
        width: '400px',
        minHeight: '580px',
        background: risk.bg,
        display: 'flex',
        flexDirection: 'column',
        fontFamily: 'system-ui, -apple-system, "Segoe UI", sans-serif',
      }}
    >
      <div
        style={{
          background: risk.headerBg,
          borderBottom: `2px solid ${risk.accent}33`,
          padding: '14px 18px 12px',
          position: 'relative',
          overflow: 'hidden',
        }}
      >
        <div
          style={{
            position: 'absolute',
            top: 0,
            left: 0,
            right: 0,
            height: '3px',
            background: riskKey !== 'LOW' ? risk.accent : 'transparent',
          }}
        />

        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                width: '38px',
                height: '38px',
                background: `${risk.accent}22`,
                border: `1.5px solid ${risk.accent}44`,
                borderRadius: '10px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '20px',
              }}
            >
              🛡️
            </div>
            <div>
              <div style={{ color: '#F0F4FF', fontSize: '14px', fontWeight: 800, letterSpacing: '-0.2px' }}>
                AI Browser Shield
              </div>
              <div style={{ color: '#3D5070', fontSize: '10px', marginTop: '1px', display: 'flex', alignItems: 'center', gap: '4px' }}>
                <div style={{ width: '6px', height: '6px', borderRadius: '50%', background: '#00C851', flexShrink: 0 }} />
                Active Protection
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: '6px', flexDirection: 'column', alignItems: 'flex-end' }}>
            {todayThreats > 0 && (
              <div
                style={{
                  background: 'rgba(255,23,68,0.15)',
                  border: '1px solid rgba(255,23,68,0.3)',
                  color: '#FF6B6B',
                  fontSize: '10px',
                  fontWeight: 700,
                  padding: '2px 8px',
                  borderRadius: '6px',
                }}
              >
                ⚠️ {todayThreats} threat{todayThreats !== 1 ? 's' : ''} today
              </div>
            )}
            {totalBlocked > 0 && (
              <div
                style={{
                  background: 'rgba(0,200,81,0.1)',
                  border: '1px solid rgba(0,200,81,0.2)',
                  color: '#00C851',
                  fontSize: '10px',
                  fontWeight: 600,
                  padding: '2px 8px',
                  borderRadius: '6px',
                }}
              >
                🛡️ {totalBlocked} blocked
              </div>
            )}
          </div>
        </div>
      </div>

      <div
        style={{
          display: 'flex',
          background: '#080E1A',
          borderBottom: '1px solid #1A2740',
        }}
      >
        {TABS.map((tab) => {
          const isActive = activeTab === tab.id
          return (
            <button
              key={tab.id}
              onClick={() => setTab(tab.id)}
              style={{
                flex: 1,
                padding: '10px 0 9px',
                background: isActive ? `${risk.accent}10` : 'transparent',
                border: 'none',
                borderBottom: `2px solid ${isActive ? risk.accent : 'transparent'}`,
                cursor: 'pointer',
                display: 'flex',
                flexDirection: 'column',
                alignItems: 'center',
                gap: '2px',
                transition: 'all 0.15s ease',
              }}
            >
              <span style={{ fontSize: '15px', lineHeight: 1 }}>{tab.icon}</span>
              <span
                style={{
                  fontSize: '9px',
                  fontWeight: 700,
                  letterSpacing: '0.5px',
                  color: isActive ? risk.accent : '#3D5070',
                  textTransform: 'uppercase',
                }}
              >
                {tab.label}
              </span>
            </button>
          )
        })}
      </div>

      <div style={{ flex: 1, overflowY: 'auto' }}>
        {activeTab === 'score' && (
          <TrustScore
            score={currentScore}
            domain={currentDomain}
            isLoading={isLoading}
            reportCount={reportCount}
            onReport={() => setTab('report')}
          />
        )}
        {activeTab === 'history' && <ThreatHistory history={history} onClear={clearAll} />}
        {activeTab === 'feed' && <CommunityFeed feed={feed} />}
        {activeTab === 'report' && (
          <ReportForm onSubmit={submitUserReport} success={reportSuccess} domain={currentDomain} />
        )}
      </div>
    </div>
  )
}
