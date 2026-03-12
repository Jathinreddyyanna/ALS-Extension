import React, { useState } from 'react'
import type { ThreatEvent } from '../../types'

interface Props {
  history: ThreatEvent[]
  onClear: () => void
}

const EVENT_META: Record<string, { icon: string; label: string; color: string }> = {
  url_threat:         { icon: '🌐', label: 'Phishing Site',      color: '#F97316' },
  redirect_chain:     { icon: '🔄', label: 'Redirect Attack',     color: '#A855F7' },
  popup_abuse:        { icon: '🪟', label: 'Popup Blocked',       color: '#3B82F6' },
  download_intercept: { icon: '📥', label: 'Download Blocked',    color: '#EF4444' },
  file_scan:          { icon: '🔍', label: 'File Scanned',        color: '#06B6D4' },
  ad_block:           { icon: '🛡️', label: 'Ad Blocked',          color: '#22C55E' },
}

const RISK_BADGE: Record<string, { bg: string; color: string }> = {
  CRITICAL: { bg: 'rgba(127,29,29,0.4)',  color: '#FCA5A5' },
  HIGH:     { bg: 'rgba(154,52,18,0.4)',  color: '#FED7AA' },
  MEDIUM:   { bg: 'rgba(113,63,18,0.4)',  color: '#FEF08A' },
  LOW:      { bg: 'rgba(20,83,45,0.4)',   color: '#86EFAC' },
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
  const meta = EVENT_META[event.eventType] || { icon: '⚠️', label: event.eventType, color: '#64748B' }
  const badge = RISK_BADGE[event.riskLevel] || RISK_BADGE.LOW

  return (
    <div
      onClick={() => setExpanded(!expanded)}
      style={{
        background: expanded ? '#111827' : '#0D1421',
        border: `1px solid ${expanded ? meta.color + '33' : '#1E293B'}`,
        borderRadius: '12px', padding: '12px 14px',
        cursor: 'pointer', transition: 'all 0.18s ease',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
        {/* Icon */}
        <div style={{
          width: '36px', height: '36px', flexShrink: 0,
          background: `${meta.color}15`,
          border: `1px solid ${meta.color}33`,
          borderRadius: '10px',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '16px',
        }}>{meta.icon}</div>

        {/* Info */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '3px' }}>
            <span style={{ color: '#E2E8F0', fontSize: '13px', fontWeight: 600 }}>{meta.label}</span>
            <span style={{
              background: badge.bg, color: badge.color,
              fontSize: '9px', fontWeight: 800, padding: '2px 7px',
              borderRadius: '100px', letterSpacing: '0.8px',
              textTransform: 'uppercase', flexShrink: 0,
            }}>{event.riskLevel}</span>
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
            <span style={{ color: '#475569', fontSize: '11px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: '200px' }}>
              {event.domain}
            </span>
            <span style={{ color: '#334155', fontSize: '10px', flexShrink: 0 }}>{timeAgo(event.timestamp)}</span>
          </div>
        </div>
      </div>

      {/* Expanded AI explanation */}
      {expanded && event.aiExplanation && (
        <div style={{
          marginTop: '10px',
          background: '#080C14', border: '1px solid #1E293B',
          borderRadius: '8px', padding: '10px 12px',
          color: '#94A3B8', fontSize: '11px', lineHeight: '1.65',
          animation: 'fade-in 0.2s ease',
        }}>
          <div style={{ color: meta.color, fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px' }}>
            AI Analysis
          </div>
          {event.aiExplanation}
        </div>
      )}
    </div>
  )
}

export function ThreatHistory({ history, onClear }: Props) {
  const [filter, setFilter] = useState<string>('all')

  const filtered = filter === 'all' ? history : history.filter(e => e.eventType === filter)

  if (history.length === 0) {
    return (
      <div style={{ padding: '48px 24px', textAlign: 'center', animation: 'fade-in 0.3s ease' }}>
        <div style={{ fontSize: '52px', marginBottom: '14px' }}>✅</div>
        <div style={{ color: '#22C55E', fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>All Clear!</div>
        <div style={{ color: '#374151', fontSize: '13px', lineHeight: '1.5' }}>
          No threats have been detected yet.<br />Your browsing history is clean.
        </div>
      </div>
    )
  }

  const categories = ['all', ...new Set(history.map(e => e.eventType))]

  return (
    <div style={{ padding: '16px', animation: 'slide-up 0.25s ease' }}>
      {/* Header */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
        <div>
          <span style={{ color: '#F1F5F9', fontSize: '13px', fontWeight: 700 }}>{history.length}</span>
          <span style={{ color: '#475569', fontSize: '12px' }}> events recorded</span>
        </div>
        <button onClick={onClear} style={{
          background: 'transparent', border: '1px solid #1E293B',
          color: '#475569', padding: '4px 12px', borderRadius: '7px',
          cursor: 'pointer', fontSize: '11px', fontWeight: 600,
          transition: 'all 0.15s ease',
        }}>Clear All</button>
      </div>

      {/* Filter chips */}
      {categories.length > 2 && (
        <div style={{ display: 'flex', gap: '6px', marginBottom: '12px', overflowX: 'auto', paddingBottom: '4px' }}>
          {categories.map(cat => {
            const meta = cat === 'all' ? { color: '#60A5FA', icon: '📋' } : (EVENT_META[cat] || { color: '#64748B', icon: '?' })
            return (
              <button key={cat} onClick={() => setFilter(cat)} style={{
                background: filter === cat ? `${meta.color}20` : 'transparent',
                border: `1px solid ${filter === cat ? meta.color + '44' : '#1E293B'}`,
                color: filter === cat ? meta.color : '#475569',
                padding: '4px 10px', borderRadius: '100px',
                fontSize: '11px', fontWeight: 600, cursor: 'pointer',
                whiteSpace: 'nowrap', transition: 'all 0.15s ease',
              }}>
                {cat === 'all' ? '📋 All' : `${meta.icon} ${EVENT_META[cat]?.label || cat}`}
              </button>
            )
          })}
        </div>
      )}

      {/* Event list */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '380px', overflowY: 'auto' }}>
        {filtered.map(event => <EventCard key={event.id} event={event} />)}
        {filtered.length === 0 && (
          <div style={{ textAlign: 'center', padding: '24px', color: '#374151', fontSize: '13px' }}>
            No events in this category
          </div>
        )}
      </div>
    </div>
  )
}
