import React, { useState } from 'react'
import type { CommunityReport } from '../../types'

interface Props { feed: CommunityReport[] }

const CAT_META: Record<string, { emoji: string; label: string; color: string }> = {
  phishing:    { emoji: '🎣', label: 'Phishing',     color: '#F97316' },
  scam:        { emoji: '💸', label: 'Scam',          color: '#EF4444' },
  malware:     { emoji: '🦠', label: 'Malware',       color: '#DC2626' },
  redirect:    { emoji: '🔄', label: 'Redirect',      color: '#A855F7' },
  popup_abuse: { emoji: '🪟', label: 'Popup Abuse',   color: '#3B82F6' },
  other:       { emoji: '⚠️', label: 'Other',         color: '#64748B' },
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 70 ? '#EF4444' : score >= 40 ? '#F97316' : '#EAB308'
  return (
    <div style={{ width: '100%', height: '3px', background: '#1E293B', borderRadius: '100px', marginTop: '6px' }}>
      <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: '100px', transition: 'width 0.5s ease' }} />
    </div>
  )
}

export function CommunityFeed({ feed }: Props) {
  const [sort, setSort] = useState<'recent' | 'risk' | 'reports'>('risk')

  if (feed.length === 0) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center', animation: 'fade-in 0.3s ease' }}>
        <div style={{ fontSize: '52px', marginBottom: '14px' }}>🌐</div>
        <div style={{ color: '#60A5FA', fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>Feed is Empty</div>
        <div style={{ color: '#374151', fontSize: '13px', lineHeight: '1.5' }}>
          No community reports in the last 24 hours.<br />Be the first to report a suspicious site!
        </div>
      </div>
    )
  }

  const sorted = [...feed].sort((a, b) => {
    if (sort === 'risk') return b.riskScore - a.riskScore
    if (sort === 'reports') return b.reports - a.reports
    return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
  })
  const totalReports = feed.reduce((sum, item) => sum + item.reports, 0)
  const highestRisk = Math.max(...feed.map(item => item.riskScore))
  const visibleFeed = sorted.slice(0, 10)

  return (
    <div style={{ padding: '16px', animation: 'slide-up 0.25s ease' }}>
      <div style={{
        background: '#0D1421',
        border: '1px solid #1E293B',
        borderRadius: '14px',
        padding: '14px',
        marginBottom: '14px',
      }}>
        <div style={{ color: '#F1F5F9', fontSize: '14px', fontWeight: 700, marginBottom: '4px' }}>
          Top Reported Threats
        </div>
        <div style={{ color: '#64748B', fontSize: '12px', lineHeight: '1.5' }}>
          Community feed shows the most reported domains from the last 24 hours, not every site ever reported.
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '8px', marginTop: '12px' }}>
          <div style={{ background: '#0A0F1A', border: '1px solid #172033', borderRadius: '10px', padding: '10px' }}>
            <div style={{ color: '#64748B', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>Domains</div>
            <div style={{ color: '#F1F5F9', fontSize: '18px', fontWeight: 800, marginTop: '2px' }}>{feed.length}</div>
          </div>
          <div style={{ background: '#0A0F1A', border: '1px solid #172033', borderRadius: '10px', padding: '10px' }}>
            <div style={{ color: '#64748B', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>Reports</div>
            <div style={{ color: '#F1F5F9', fontSize: '18px', fontWeight: 800, marginTop: '2px' }}>{totalReports}</div>
          </div>
          <div style={{ background: '#0A0F1A', border: '1px solid #172033', borderRadius: '10px', padding: '10px' }}>
            <div style={{ color: '#64748B', fontSize: '10px', textTransform: 'uppercase', fontWeight: 700 }}>Top Risk</div>
            <div style={{ color: '#FCA5A5', fontSize: '18px', fontWeight: 800, marginTop: '2px' }}>{highestRisk}</div>
          </div>
        </div>
      </div>

      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <div>
          <span style={{ color: '#F1F5F9', fontSize: '13px', fontWeight: 700 }}>{visibleFeed.length}</span>
          <span style={{ color: '#475569', fontSize: '12px' }}> ranked results</span>
          {feed.length > visibleFeed.length && (
            <div style={{ color: '#334155', fontSize: '10px', marginTop: '2px' }}>
              Showing top {visibleFeed.length} of {feed.length}
            </div>
          )}
        </div>
        <div style={{ display: 'flex', gap: '4px' }}>
          {(['risk', 'reports', 'recent'] as const).map(s => (
            <button key={s} onClick={() => setSort(s)} style={{
              background: sort === s ? 'rgba(59,130,246,0.2)' : 'transparent',
              border: `1px solid ${sort === s ? 'rgba(59,130,246,0.4)' : '#1E293B'}`,
              color: sort === s ? '#60A5FA' : '#475569',
              padding: '3px 8px', borderRadius: '6px',
              fontSize: '10px', fontWeight: 600, cursor: 'pointer',
              textTransform: 'capitalize',
            }}>{s}</button>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '400px', overflowY: 'auto' }}>
        {visibleFeed.map((item, i) => {
          const cat = CAT_META[item.category] || CAT_META.other
          const riskColor = item.riskScore >= 70 ? '#EF4444' : item.riskScore >= 40 ? '#F97316' : '#EAB308'
          return (
            <div key={i} style={{
              background: '#0D1421', border: '1px solid #1E293B',
              borderRadius: '12px', padding: '12px 14px',
              transition: 'border-color 0.2s ease',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                {/* Rank */}
                <div style={{
                  width: '22px', height: '22px', flexShrink: 0,
                  background: i < 3 ? 'rgba(239,68,68,0.15)' : '#0F172A',
                  border: `1px solid ${i < 3 ? 'rgba(239,68,68,0.3)' : '#1E293B'}`,
                  borderRadius: '6px',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  color: i < 3 ? '#FCA5A5' : '#334155',
                  fontSize: '10px', fontWeight: 800,
                }}>
                  {i + 1}
                </div>

                {/* Category icon */}
                <div style={{
                  width: '34px', height: '34px', flexShrink: 0,
                  background: `${cat.color}15`,
                  border: `1px solid ${cat.color}33`,
                  borderRadius: '9px',
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: '16px',
                }}>{cat.emoji}</div>

                {/* Domain + category */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    color: '#E2E8F0', fontSize: '13px', fontWeight: 600,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                    marginBottom: '2px',
                  }}>{item.domain}</div>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ color: cat.color, fontSize: '10px', fontWeight: 600 }}>{cat.label}</span>
                    <span style={{ color: '#334155', fontSize: '10px' }}>·</span>
                    <span style={{
                      color: '#93C5FD',
                      fontSize: '10px',
                      fontWeight: 700,
                      background: 'rgba(59,130,246,0.12)',
                      border: '1px solid rgba(59,130,246,0.25)',
                      borderRadius: '999px',
                      padding: '2px 6px',
                    }}>
                      Reported {item.reports} time{item.reports !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <ScoreBar score={item.riskScore} />
                </div>

                {/* Risk score badge */}
                <div style={{
                  flexShrink: 0, textAlign: 'center',
                  background: `${riskColor}15`,
                  border: `1px solid ${riskColor}33`,
                  borderRadius: '8px', padding: '5px 10px',
                }}>
                  <div style={{ color: riskColor, fontSize: '16px', fontWeight: 800, lineHeight: 1 }}>{item.riskScore}</div>
                  <div style={{ color: '#374151', fontSize: '8px', fontWeight: 600, marginTop: '1px' }}>RISK</div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
