import React, { useState, useEffect } from 'react'

interface Props {
  url: string
  score: number
  explanation: string
  onDismiss: () => void
  onGoBack: () => void
  onReport: () => void
}

export function WarningBanner({ url, score, explanation, onDismiss, onGoBack, onReport }: Props) {
  const [visible, setVisible] = useState(false)
  const [expanded, setExpanded] = useState(false)

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))
  }, [])

  const domain = (() => { try { return new URL(url).hostname } catch { return url } })()

  return (
    <div style={{
      position: 'fixed', top: 0, left: 0, right: 0, zIndex: 2147483647,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
      transform: visible ? 'translateY(0)' : 'translateY(-100%)',
      transition: 'transform 0.35s cubic-bezier(0.34, 1.56, 0.64, 1)',
    }}>
      {/* Main bar */}
      <div style={{
        background: 'linear-gradient(135deg, #1C1917 0%, #292524 50%, #1C1917 100%)',
        borderBottom: '1px solid #F97316',
        boxShadow: '0 4px 32px rgba(249,115,22,0.3), 0 2px 8px rgba(0,0,0,0.8)',
        padding: '0 20px',
      }}>
        {/* Top accent line */}
        <div style={{
          height: '3px',
          background: 'linear-gradient(90deg, transparent, #F97316, #EF4444, #F97316, transparent)',
          marginBottom: '12px',
        }} />

        <div style={{ display: 'flex', alignItems: 'center', gap: '14px', paddingBottom: '12px' }}>
          {/* Icon */}
          <div style={{
            width: '40px', height: '40px', flexShrink: 0,
            background: 'linear-gradient(135deg, #9A3412, #EA580C)',
            borderRadius: '12px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            boxShadow: '0 0 16px rgba(249,115,22,0.5)',
            fontSize: '20px',
          }}>⚠️</div>

          {/* Text */}
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px', marginBottom: '3px' }}>
              <span style={{
                color: '#FED7AA', fontSize: '14px', fontWeight: 700, letterSpacing: '0.01em'
              }}>Suspicious Website Detected</span>
              <span style={{
                background: 'linear-gradient(135deg, #9A3412, #EA580C)',
                color: '#FED7AA', fontSize: '10px', fontWeight: 800,
                padding: '2px 8px', borderRadius: '100px',
                letterSpacing: '1.5px', textTransform: 'uppercase',
              }}>HIGH · {score}/100</span>
            </div>
            <div style={{
              color: '#9CA3AF', fontSize: '12px', overflow: 'hidden',
              textOverflow: 'ellipsis', whiteSpace: 'nowrap',
            }}>{domain}</div>
          </div>

          {/* Actions */}
          <div style={{ display: 'flex', gap: '8px', flexShrink: 0 }}>
            <button onClick={onGoBack} style={{
              background: 'linear-gradient(135deg, #166534, #15803D)',
              color: '#D1FAE5', border: 'none', padding: '8px 16px',
              borderRadius: '8px', fontSize: '12px', fontWeight: 700,
              cursor: 'pointer', boxShadow: '0 2px 8px rgba(22,101,52,0.4)',
              transition: 'all 0.15s ease',
            }}>← Go Back</button>

            <button onClick={() => setExpanded(!expanded)} style={{
              background: 'rgba(255,255,255,0.08)', color: '#D1D5DB',
              border: '1px solid rgba(255,255,255,0.12)', padding: '8px 12px',
              borderRadius: '8px', fontSize: '12px', cursor: 'pointer',
              transition: 'all 0.15s ease',
            }}>{expanded ? '▲' : '▼'} Details</button>

            <button onClick={onReport} style={{
              background: 'rgba(59,130,246,0.15)', color: '#93C5FD',
              border: '1px solid rgba(59,130,246,0.3)', padding: '8px 12px',
              borderRadius: '8px', fontSize: '12px', cursor: 'pointer',
            }}>🚩 Report</button>

            <button onClick={onDismiss} style={{
              background: 'rgba(255,255,255,0.06)', color: '#6B7280',
              border: '1px solid rgba(255,255,255,0.08)', padding: '8px 12px',
              borderRadius: '8px', fontSize: '12px', cursor: 'pointer',
            }}>✕</button>
          </div>
        </div>

        {/* Expandable details */}
        {expanded && (
          <div style={{
            borderTop: '1px solid rgba(249,115,22,0.2)',
            paddingTop: '12px', paddingBottom: '14px',
            animation: 'absSlideDown 0.2s ease',
          }}>
            <div style={{ display: 'flex', gap: '16px', alignItems: 'flex-start' }}>
              <div style={{ flex: 1 }}>
                <div style={{ color: '#F97316', fontSize: '11px', fontWeight: 600, marginBottom: '6px', textTransform: 'uppercase', letterSpacing: '1px' }}>
                  AI Analysis
                </div>
                <div style={{ color: '#D1D5DB', fontSize: '13px', lineHeight: '1.6' }}>{explanation}</div>
              </div>
              <div style={{
                background: 'rgba(249,115,22,0.1)', border: '1px solid rgba(249,115,22,0.2)',
                borderRadius: '10px', padding: '12px 16px', flexShrink: 0, textAlign: 'center',
              }}>
                <div style={{ color: '#F97316', fontSize: '28px', fontWeight: 800 }}>{score}</div>
                <div style={{ color: '#78716C', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', marginTop: '2px' }}>Risk Score</div>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
