import React, { useEffect } from 'react'
import { useStore } from './store'
import { TrustScore } from './components/TrustScore'
import { ThreatHistory } from './components/ThreatHistory'
import { CommunityFeed } from './components/CommunityFeed'
import { ReportForm } from './components/ReportForm'
import { EmailScanner } from './components/EmailScanner'

type Tab = 'score' | 'mail' | 'history' | 'feed' | 'report'

const TABS: { id: Tab; emoji: string; label: string }[] = [
  { id: 'score', emoji: '🛡️', label: 'Shield' },
  { id: 'mail', emoji: '📨', label: 'Mail' },
  { id: 'history', emoji: '📜', label: 'History' },
  { id: 'feed', emoji: '🌐', label: 'Feed' },
  { id: 'report', emoji: '🚩', label: 'Report' },
]

const RISK_HEADER: Record<string, { border: string; glow: string }> = {
  CRITICAL: { border: '#EF4444', glow: 'rgba(239,68,68,0.15)' },
  HIGH: { border: '#F97316', glow: 'rgba(249,115,22,0.12)' },
  MEDIUM: { border: '#EAB308', glow: 'rgba(234,179,8,0.1)' },
  LOW: { border: '#1E3A5F', glow: 'transparent' },
}

function getRiskKey(score: number | null): string {
  if (score === null) return 'LOW'
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

export default function App() {
  const {
    history, feed, emailAnalysis, currentScore, currentDomain, currentExplanation,
    activeTab, isLoading, reportSuccess,
    loadAll, setTab, submitUserReport, clearAll,
  } = useStore()

  useEffect(() => {
    loadAll()
    const params = new URLSearchParams(window.location.search)
    if (params.get('tab') === 'report') setTab('report')
  }, [])

  const riskKey = getRiskKey(currentScore)
  const riskStyle = RISK_HEADER[riskKey]
  const todayThreats = history.filter(e => Date.now() - e.timestamp < 86400000).length

  return (
    <div style={{
      width: '400px',
      minHeight: '560px',
      background: '#080C14',
      display: 'flex',
      flexDirection: 'column',
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
    }}>
      <div style={{
        background: 'linear-gradient(135deg, #0D1421 0%, #0A1020 100%)',
        borderBottom: `1px solid ${riskStyle.border}44`,
        boxShadow: `0 4px 24px ${riskStyle.glow}`,
        padding: '14px 18px 12px',
        position: 'relative',
        overflow: 'hidden',
      }}>
        <div style={{
          position: 'absolute',
          inset: 0,
          opacity: 0.03,
          backgroundImage: 'radial-gradient(circle at 20% 50%, #3B82F6 0%, transparent 50%), radial-gradient(circle at 80% 20%, #8B5CF6 0%, transparent 50%)',
          pointerEvents: 'none',
        }} />

        <div style={{ position: 'relative', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
            <div style={{
              width: '40px',
              height: '40px',
              background: 'linear-gradient(135deg, #1E3A8A, #1D4ED8)',
              borderRadius: '12px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '20px',
              boxShadow: '0 4px 12px rgba(29,78,216,0.4)',
            }}>🛡️</div>
            <div>
              <div style={{ color: '#F1F5F9', fontSize: '15px', fontWeight: 800, letterSpacing: '-0.3px' }}>
                AI Browser Shield
              </div>
              <div style={{ color: '#334155', fontSize: '11px', marginTop: '1px' }}>
                Web + email protection active
              </div>
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            {todayThreats > 0 && (
              <div style={{
                background: 'rgba(239,68,68,0.15)',
                border: '1px solid rgba(239,68,68,0.3)',
                color: '#FCA5A5',
                fontSize: '11px',
                fontWeight: 700,
                padding: '3px 8px',
                borderRadius: '7px',
              }}>
                {todayThreats} threat{todayThreats !== 1 ? 's' : ''} today
              </div>
            )}
            <div style={{ position: 'relative' }}>
              <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: '#22C55E' }} />
              <div style={{
                position: 'absolute',
                inset: '-3px',
                borderRadius: '50%',
                border: '2px solid rgba(34,197,94,0.3)',
                animation: 'pulse-ring 2s ease-in-out infinite',
              }} />
            </div>
          </div>
        </div>
      </div>

      <div style={{
        display: 'flex',
        background: '#0A0F1A',
        borderBottom: '1px solid #0F172A',
        padding: '0 4px',
      }}>
        {TABS.map(tab => {
          const isActive = activeTab === tab.id
          return (
            <button key={tab.id} onClick={() => setTab(tab.id)} style={{
              flex: 1,
              padding: '11px 0 10px',
              background: 'transparent',
              border: 'none',
              borderBottom: `2px solid ${isActive ? '#3B82F6' : 'transparent'}`,
              cursor: 'pointer',
              transition: 'all 0.18s ease',
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              gap: '3px',
            }}>
              <span style={{ fontSize: '16px', lineHeight: 1 }}>{tab.emoji}</span>
              <span style={{
                fontSize: '10px',
                fontWeight: 700,
                letterSpacing: '0.3px',
                color: isActive ? '#60A5FA' : '#334155',
                transition: 'color 0.18s ease',
              }}>{tab.label}</span>
            </button>
          )
        })}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', background: '#080C14' }}>
        {activeTab === 'score' && (
          <TrustScore score={currentScore} domain={currentDomain} explanation={currentExplanation} isLoading={isLoading} />
        )}
        {activeTab === 'mail' && (
          <EmailScanner analysis={emailAnalysis} />
        )}
        {activeTab === 'history' && (
          <ThreatHistory history={history} onClear={clearAll} />
        )}
        {activeTab === 'feed' && (
          <CommunityFeed feed={feed} />
        )}
        {activeTab === 'report' && (
          <ReportForm
            onSubmit={submitUserReport}
            success={reportSuccess}
            domain={currentDomain}
          />
        )}
      </div>

      <div style={{
        background: '#060A12',
        borderTop: '1px solid #0F172A',
        padding: '8px 16px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div style={{ color: '#1E3A5F', fontSize: '11px' }}>
          AI Browser Shield v1.0
        </div>
        <button onClick={() => setTab('report')} style={{
          background: 'rgba(239,68,68,0.08)',
          border: '1px solid rgba(239,68,68,0.2)',
          color: '#FCA5A5',
          padding: '4px 12px',
          borderRadius: '7px',
          cursor: 'pointer',
          fontSize: '11px',
          fontWeight: 600,
          transition: 'all 0.15s ease',
        }}>🚩 Report This Site</button>
      </div>
    </div>
  )
}
