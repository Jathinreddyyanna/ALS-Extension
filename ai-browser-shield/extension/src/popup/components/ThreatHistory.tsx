import React, { useState } from 'react'
import type { ThreatEvent } from '../../types'

interface Props {
  history: ThreatEvent[]
  onClear: () => void
}

const EVENT_META: Record<string, { icon: string; label: string; color: string }> = {
  url_threat: { icon: '🌐', label: 'Dangerous Site', color: '#FF6B00' },
  redirect_chain: { icon: '🔁', label: 'Redirect Trap', color: '#A855F7' },
  popup_abuse: { icon: '🪟', label: 'Popup Abuse', color: '#60A5FA' },
  download_intercept: { icon: '📥', label: 'Risky Download', color: '#FF1744' },
  file_scan: { icon: '🔍', label: 'File Scanned', color: '#22D3EE' },
  ad_block: { icon: '🛡️', label: 'Tracker Blocked', color: '#00C851' },
}

const RISK_BADGE: Record<string, { bg: string; color: string }> = {
  CRITICAL: { bg: 'rgba(255,23,68,0.15)', color: '#FF6B6B' },
  HIGH: { bg: 'rgba(255,107,0,0.15)', color: '#FF9A4D' },
  MEDIUM: { bg: 'rgba(255,179,0,0.15)', color: '#FFD166' },
  LOW: { bg: 'rgba(0,200,81,0.12)', color: '#00E676' },
}

function timeAgo(ts: number): string {
  const diff = Date.now() - ts
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return `${Math.floor(diff / 86400000)}d ago`
}

function EventCard({ event }: { event: ThreatEvent }) {
  const [expanded, setExpanded] = useState(false)
  const meta = EVENT_META[event.eventType] || { icon: '⚠️', label: 'Alert', color: '#8899BB' }
  const badge = RISK_BADGE[event.riskLevel] || RISK_BADGE.LOW

  return (
    <div
      onClick={() => setExpanded((value) => !value)}
      style={{
        background: expanded ? '#111D2E' : '#0D1524',
        border: `1px solid ${expanded ? `${meta.color}44` : '#1A2740'}`,
        borderRadius: '14px',
        padding: '14px 16px',
        cursor: 'pointer',
        transition: 'all 0.18s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '12px' }}>
        <div
          style={{
            width: '40px',
            height: '40px',
            flexShrink: 0,
            background: `${meta.color}14`,
            border: `1px solid ${meta.color}30`,
            borderRadius: '12px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '18px',
          }}
        >
          {meta.icon}
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '8px', marginBottom: '4px' }}>
            <span style={{ color: '#F0F4FF', fontSize: '14px', fontWeight: 700 }}>{meta.label}</span>
            <span
              style={{
                background: badge.bg,
                color: badge.color,
                fontSize: '10px',
                fontWeight: 800,
                padding: '3px 8px',
                borderRadius: '999px',
                letterSpacing: '0.8px',
                textTransform: 'uppercase',
                flexShrink: 0,
              }}
            >
              {event.riskLevel}
            </span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', gap: '8px' }}>
            <span style={{ color: '#8899BB', fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {event.domain}
            </span>
            <span style={{ color: '#3D5070', fontSize: '11px', flexShrink: 0 }}>{timeAgo(event.timestamp)}</span>
          </div>
        </div>
      </div>

      {expanded && event.aiExplanation && (
        <div
          style={{
            marginTop: '12px',
            background: '#060B14',
            border: '1px solid #1A2740',
            borderRadius: '10px',
            padding: '12px 14px',
            color: '#8899BB',
            fontSize: '12px',
            lineHeight: '1.65',
          }}
        >
          <div style={{ color: meta.color, fontSize: '10px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>
            What happened
          </div>
          {event.aiExplanation}
        </div>
      )}
    </div>
  )
}

export function ThreatHistory({ history, onClear }: Props) {
  const [filter, setFilter] = useState<string>('all')
  const filtered = filter === 'all' ? history : history.filter((e) => e.eventType === filter)

  if (history.length === 0) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center' }}>
        <div style={{ fontSize: '52px', marginBottom: '16px' }}>✅</div>
        <div style={{ color: '#00C851', fontSize: '17px', fontWeight: 800, marginBottom: '6px' }}>
          All Clear!
        </div>
        <div style={{ color: '#3D5070', fontSize: '13px', lineHeight: '1.6' }}>
          No threats detected in your browsing session.
          <br />
          AI Browser Shield is actively protecting you.
        </div>
      </div>
    )
  }

  const categories = ['all', ...new Set(history.map((e) => e.eventType))]

  return (
    <div style={{ padding: '16px' }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '14px' }}>
        <div>
          <div style={{ color: '#F0F4FF', fontSize: '14px', fontWeight: 800 }}>{history.length} alerts saved</div>
          <div style={{ color: '#3D5070', fontSize: '11px', marginTop: '2px' }}>Tap any card to see what happened</div>
        </div>
        <button
          onClick={onClear}
          style={{
            background: '#0D1524',
            border: '1px solid #1A2740',
            color: '#8899BB',
            padding: '6px 12px',
            borderRadius: '8px',
            cursor: 'pointer',
            fontSize: '11px',
            fontWeight: 700,
          }}
        >
          Clear
        </button>
      </div>

      {categories.length > 2 && (
        <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', overflowX: 'auto', paddingBottom: '2px' }}>
          {categories.map((cat) => {
            const meta = cat === 'all' ? { color: '#60A5FA', icon: '📋', label: 'All' } : (EVENT_META[cat] || { color: '#8899BB', icon: '⚠️', label: cat })
            return (
              <button
                key={cat}
                onClick={() => setFilter(cat)}
                style={{
                  background: filter === cat ? `${meta.color}14` : '#0D1524',
                  border: `1px solid ${filter === cat ? `${meta.color}40` : '#1A2740'}`,
                  color: filter === cat ? meta.color : '#8899BB',
                  padding: '6px 10px',
                  borderRadius: '999px',
                  fontSize: '11px',
                  fontWeight: 700,
                  cursor: 'pointer',
                  whiteSpace: 'nowrap',
                }}
              >
                {meta.icon} {meta.label}
              </button>
            )
          })}
        </div>
      )}

      <div style={{ display: 'flex', flexDirection: 'column', gap: '8px', maxHeight: '400px', overflowY: 'auto' }}>
        {filtered.map((event) => <EventCard key={event.id} event={event} />)}
        {filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '24px', color: '#3D5070', fontSize: '13px' }}>
            No alerts in this category
          </div>
        )}
      </div>
    </div>
  )
}
