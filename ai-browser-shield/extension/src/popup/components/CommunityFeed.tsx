import React, { useMemo, useState } from 'react'
import type { CommunityReport } from '../../types'

interface Props {
  feed: CommunityReport[]
}

const CAT_META: Record<string, { emoji: string; label: string; color: string }> = {
  phishing: { emoji: '🎣', label: 'Phishing', color: '#FF6B00' },
  scam: { emoji: '💸', label: 'Scam', color: '#FF1744' },
  malware: { emoji: '🦠', label: 'Malware', color: '#FF1744' },
  redirect: { emoji: '🔁', label: 'Redirect', color: '#A855F7' },
  popup_abuse: { emoji: '🪟', label: 'Popup Abuse', color: '#60A5FA' },
  other: { emoji: '⚠️', label: 'Other', color: '#8899BB' },
}

function ScoreBar({ score }: { score: number }) {
  const color = score >= 70 ? '#FF1744' : score >= 40 ? '#FF6B00' : '#FFB300'
  return (
    <div style={{ width: '100%', height: '4px', background: '#1A2740', borderRadius: '999px', marginTop: '8px' }}>
      <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: '999px', transition: 'width 0.4s ease' }} />
    </div>
  )
}

export function CommunityFeed({ feed }: Props) {
  const [sort, setSort] = useState<'recent' | 'risk' | 'reports'>('risk')

  const sorted = useMemo(() => {
    return [...feed].sort((a, b) => {
      if (sort === 'risk') return b.riskScore - a.riskScore
      if (sort === 'reports') return b.reports - a.reports
      return new Date(b.lastSeen).getTime() - new Date(a.lastSeen).getTime()
    })
  }, [feed, sort])

  if (feed.length === 0) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center' }}>
        <div style={{ fontSize: '52px', marginBottom: '16px' }}>🌐</div>
        <div style={{ color: '#60A5FA', fontSize: '17px', fontWeight: 800, marginBottom: '8px' }}>
          Community Feed Empty
        </div>
        <div style={{ color: '#3D5070', fontSize: '13px', lineHeight: '1.6' }}>
          When other users report dangerous sites,
          <br />
          they appear here to warn everyone.
          <br />
          <br />
          <span style={{ color: '#8899BB' }}>Help protect others — report suspicious sites you find!</span>
        </div>
      </div>
    )
  }

  return (
    <div style={{ padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '10px', marginBottom: '14px' }}>
        <div>
          <div style={{ color: '#F0F4FF', fontSize: '13px', fontWeight: 700 }}>
            Threats Others Reported
          </div>
          <div style={{ color: '#3D5070', fontSize: '11px', marginTop: '2px' }}>
            {feed.length} dangerous site{feed.length !== 1 ? 's' : ''} flagged by community
          </div>
        </div>
        <div style={{ display: 'flex', gap: '6px' }}>
          {(['risk', 'reports', 'recent'] as const).map((s) => (
            <button
              key={s}
              onClick={() => setSort(s)}
              style={{
                background: sort === s ? 'rgba(37,99,235,0.14)' : '#0D1524',
                border: `1px solid ${sort === s ? 'rgba(96,165,250,0.35)' : '#1A2740'}`,
                color: sort === s ? '#60A5FA' : '#8899BB',
                padding: '6px 10px',
                borderRadius: '8px',
                fontSize: '11px',
                fontWeight: 700,
                cursor: 'pointer',
                textTransform: 'capitalize',
              }}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '410px', overflowY: 'auto' }}>
        {sorted.map((item, i) => {
          const cat = CAT_META[item.category] || CAT_META.other
          const riskColor = item.riskScore >= 70 ? '#FF1744' : item.riskScore >= 40 ? '#FF6B00' : '#FFB300'
          return (
            <div
              key={`${item.domain}-${item.category}-${i}`}
              style={{
                background: '#0D1524',
                border: '1px solid #1A2740',
                borderRadius: '14px',
                padding: '14px 16px',
              }}
            >
              <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
                <div
                  style={{
                    width: '24px',
                    height: '24px',
                    flexShrink: 0,
                    background: i < 3 ? 'rgba(255,23,68,0.14)' : '#111D2E',
                    border: `1px solid ${i < 3 ? 'rgba(255,23,68,0.28)' : '#1A2740'}`,
                    borderRadius: '7px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: i < 3 ? '#FF6B6B' : '#8899BB',
                    fontSize: '11px',
                    fontWeight: 800,
                  }}
                >
                  {i + 1}
                </div>

                <div
                  style={{
                    width: '38px',
                    height: '38px',
                    flexShrink: 0,
                    background: `${cat.color}15`,
                    border: `1px solid ${cat.color}33`,
                    borderRadius: '11px',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '18px',
                  }}
                >
                  {cat.emoji}
                </div>

                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ color: '#F0F4FF', fontSize: '13px', fontWeight: 700, marginBottom: '3px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {item.domain}
                  </div>
                  <div style={{ display: 'flex', gap: '6px', alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={{ color: cat.color, fontSize: '11px', fontWeight: 700 }}>{cat.label}</span>
                    <span style={{ color: '#3D5070', fontSize: '10px' }}>•</span>
                    <span style={{ color: '#8899BB', fontSize: '11px' }}>{item.reports} report{item.reports !== 1 ? 's' : ''}</span>
                  </div>
                  <ScoreBar score={item.riskScore} />
                </div>

                <div
                  style={{
                    flexShrink: 0,
                    textAlign: 'center',
                    background: `${riskColor}14`,
                    border: `1px solid ${riskColor}33`,
                    borderRadius: '10px',
                    padding: '6px 10px',
                  }}
                >
                  <div style={{ color: riskColor, fontSize: '18px', fontWeight: 900, lineHeight: 1 }}>{item.riskScore}</div>
                  <div style={{ color: '#3D5070', fontSize: '9px', fontWeight: 700, marginTop: '2px' }}>RISK</div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
