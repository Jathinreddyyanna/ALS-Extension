import React, { useState, useEffect } from 'react'

interface Props {
  url: string
  score: number
  explanation: string
  indicators?: string[]
  onGoBack: () => void
  onProceed?: () => void
  onReport: () => void
}

export function BlockScreen({ url, score, explanation, indicators = [], onGoBack, onProceed, onReport }: Props) {
  const [visible, setVisible] = useState(false)
  const [proceedCountdown, setProceedCountdown] = useState(10)
  const [proceedEnabled, setProceedEnabled] = useState(false)

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))

    // Only allow proceed after countdown
    const timer = setInterval(() => {
      setProceedCountdown(c => {
        if (c <= 1) { clearInterval(timer); setProceedEnabled(true); return 0 }
        return c - 1
      })
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  const domain = (() => { try { return new URL(url).hostname } catch { return url } })()

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 2147483647,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
      background: 'radial-gradient(ellipse at center, #1A0505 0%, #0A0A0F 60%, #000 100%)',
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      opacity: visible ? 1 : 0,
      transition: 'opacity 0.4s ease',
    }}>
      {/* Animated background grid */}
      <div style={{
        position: 'absolute', inset: 0, opacity: 0.03,
        backgroundImage: 'linear-gradient(rgba(239,68,68,0.8) 1px, transparent 1px), linear-gradient(90deg, rgba(239,68,68,0.8) 1px, transparent 1px)',
        backgroundSize: '40px 40px',
      }} />

      {/* Radial danger glow */}
      <div style={{
        position: 'absolute', top: '50%', left: '50%',
        transform: 'translate(-50%, -50%)',
        width: '600px', height: '600px',
        background: 'radial-gradient(circle, rgba(127,29,29,0.3) 0%, transparent 70%)',
        pointerEvents: 'none',
      }} />

      {/* Main card */}
      <div style={{
        position: 'relative', zIndex: 1,
        background: 'linear-gradient(145deg, rgba(30,10,10,0.95) 0%, rgba(15,10,10,0.98) 100%)',
        border: '1px solid rgba(239,68,68,0.4)',
        borderRadius: '24px', padding: '48px 40px',
        maxWidth: '560px', width: '90%',
        boxShadow: '0 0 0 1px rgba(239,68,68,0.1), 0 32px 80px rgba(0,0,0,0.9), 0 0 60px rgba(127,29,29,0.3)',
        transform: visible ? 'scale(1) translateY(0)' : 'scale(0.95) translateY(20px)',
        transition: 'transform 0.4s cubic-bezier(0.34, 1.2, 0.64, 1)',
      }}>
        {/* Shield icon with pulse */}
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div style={{
            display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
            width: '80px', height: '80px',
            background: 'linear-gradient(135deg, #7F1D1D, #991B1B)',
            borderRadius: '24px',
            boxShadow: '0 0 0 8px rgba(127,29,29,0.15), 0 0 0 16px rgba(127,29,29,0.07)',
            fontSize: '40px',
            animation: 'absPulse 2s ease-in-out infinite',
          }}>🛡️</div>
        </div>

        {/* Badge */}
        <div style={{ textAlign: 'center', marginBottom: '16px' }}>
          <span style={{
            display: 'inline-block',
            background: 'linear-gradient(135deg, rgba(127,29,29,0.8), rgba(153,27,27,0.8))',
            border: '1px solid rgba(239,68,68,0.4)',
            color: '#FCA5A5', fontSize: '11px', fontWeight: 800,
            padding: '5px 16px', borderRadius: '100px',
            letterSpacing: '2px', textTransform: 'uppercase',
          }}>🚨 CRITICAL THREAT — {score}/100</span>
        </div>

        {/* Title */}
        <h1 style={{
          color: '#FFF', fontSize: '24px', fontWeight: 800,
          textAlign: 'center', margin: '0 0 12px',
          letterSpacing: '-0.02em',
        }}>This Page Has Been Blocked</h1>

        {/* Domain */}
        <div style={{
          background: 'rgba(239,68,68,0.08)', border: '1px solid rgba(239,68,68,0.2)',
          borderRadius: '10px', padding: '12px 16px', marginBottom: '20px',
          display: 'flex', alignItems: 'center', gap: '10px',
        }}>
          <span style={{ fontSize: '16px' }}>🔗</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ color: '#6B7280', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', marginBottom: '2px' }}>Blocked URL</div>
            <div style={{ color: '#FCA5A5', fontSize: '12px', wordBreak: 'break-all', fontFamily: 'monospace' }}>{url.slice(0, 80)}{url.length > 80 ? '…' : ''}</div>
          </div>
        </div>

        {/* AI Explanation */}
        <div style={{
          background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)',
          borderRadius: '12px', padding: '16px', marginBottom: '20px',
        }}>
          <div style={{ color: '#EF4444', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            🤖 AI Security Analysis
          </div>
          <p style={{ color: '#D1D5DB', fontSize: '13px', lineHeight: '1.7', margin: 0 }}>{explanation}</p>
        </div>

        {/* Indicators */}
        {indicators.length > 0 && (
          <div style={{ marginBottom: '24px' }}>
            <div style={{ color: '#6B7280', fontSize: '11px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
              Red Flags Detected
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {indicators.map((ind, i) => (
                <span key={i} style={{
                  background: 'rgba(239,68,68,0.1)', border: '1px solid rgba(239,68,68,0.2)',
                  color: '#FCA5A5', fontSize: '11px', padding: '4px 10px', borderRadius: '6px',
                }}>⚡ {ind}</span>
              ))}
            </div>
          </div>
        )}

        {/* Buttons */}
        <div style={{ display: 'flex', gap: '10px' }}>
          <button onClick={onGoBack} style={{
            flex: 2,
            background: 'linear-gradient(135deg, #166534, #15803D)',
            color: '#D1FAE5', border: 'none', padding: '14px',
            borderRadius: '12px', fontSize: '15px', fontWeight: 700,
            cursor: 'pointer', boxShadow: '0 4px 20px rgba(22,101,52,0.4)',
            transition: 'all 0.2s ease',
          }}>← Leave This Page (Safe)</button>

          <button onClick={onReport} style={{
            flex: 1,
            background: 'rgba(59,130,246,0.12)', color: '#93C5FD',
            border: '1px solid rgba(59,130,246,0.25)', padding: '14px',
            borderRadius: '12px', fontSize: '14px', fontWeight: 600,
            cursor: 'pointer', transition: 'all 0.2s ease',
          }}>🚩 Report</button>
        </div>

        {/* Proceed anyway - only after countdown */}
        {onProceed && (
          <div style={{ textAlign: 'center', marginTop: '16px' }}>
            <button
              onClick={proceedEnabled ? onProceed : undefined}
              style={{
                background: 'transparent', border: 'none',
                color: proceedEnabled ? '#6B7280' : '#374151',
                fontSize: '12px', cursor: proceedEnabled ? 'pointer' : 'default',
                padding: '4px 8px', borderRadius: '6px',
                transition: 'color 0.3s ease',
                textDecoration: proceedEnabled ? 'underline' : 'none',
              }}
            >
              {proceedEnabled ? 'I understand the risk — proceed anyway' : `Proceed option available in ${proceedCountdown}s…`}
            </button>
          </div>
        )}

        {/* Footer */}
        <div style={{
          borderTop: '1px solid rgba(255,255,255,0.06)',
          marginTop: '20px', paddingTop: '16px',
          display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '6px',
        }}>
          <span style={{ fontSize: '14px' }}>🛡️</span>
          <span style={{ color: '#374151', fontSize: '11px' }}>Protected by AI Browser Shield</span>
        </div>
      </div>
    </div>
  )
}
