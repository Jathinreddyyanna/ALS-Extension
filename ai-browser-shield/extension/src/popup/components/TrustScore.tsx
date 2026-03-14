import React, { useEffect, useState } from 'react'

interface Props {
  score: number | null
  domain: string
  explanation?: string
  isLoading?: boolean
}

const RISK_LEVELS = {
  CRITICAL: { label: 'CRITICAL', color: '#EF4444', glow: '#EF444433', bg: '#450A0A', ring: '#EF4444', emoji: '🚨', msg: 'Dangerous site detected. Do not enter any information.' },
  HIGH:     { label: 'HIGH RISK', color: '#F97316', glow: '#F9731633', bg: '#431407', ring: '#F97316', emoji: '⚠️', msg: 'Suspicious site. Be very cautious with any data you share.' },
  MEDIUM:   { label: 'CAUTION',   color: '#EAB308', glow: '#EAB30833', bg: '#422006', ring: '#EAB308', emoji: '🔶', msg: 'Some unusual patterns. Verify this site before proceeding.' },
  LOW:      { label: 'SAFE',      color: '#22C55E', glow: '#22C55E33', bg: '#052E16', ring: '#22C55E', emoji: '✅', msg: 'No threats detected. This site appears safe.' },
  UNKNOWN:  { label: 'UNSCORED',  color: '#64748B', glow: '#64748B22', bg: '#1E293B', ring: '#334155', emoji: '🔍', msg: 'No data available for this site yet.' },
}

function getRisk(score: number | null) {
  if (score === null) return RISK_LEVELS.UNKNOWN
  if (score >= 80) return RISK_LEVELS.CRITICAL
  if (score >= 60) return RISK_LEVELS.HIGH
  if (score >= 30) return RISK_LEVELS.MEDIUM
  return RISK_LEVELS.LOW
}

export function TrustScore({ score, domain, explanation, isLoading }: Props) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const risk = getRisk(score)
  const pct = score ?? 0
  const R = 52
  const circumference = 2 * Math.PI * R
  const offset = circumference - (animatedScore / 100) * circumference

  useEffect(() => {
    if (score === null) return
    const start = Date.now()
    const duration = 900
    const animate = () => {
      const elapsed = Date.now() - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3) // ease-out cubic
      setAnimatedScore(Math.round(score * eased))
      if (progress < 1) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [score])

  if (isLoading) {
    return (
      <div style={{ padding: '32px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
        <div style={{
          width: '120px', height: '120px', borderRadius: '50%',
          background: 'linear-gradient(135deg, #1E293B, #0F172A)',
          border: '8px solid #1E293B',
          animation: 'pulse-ring 1.5s ease-in-out infinite',
        }} />
        <div style={{ background: '#1E293B', borderRadius: '8px', height: '20px', width: '120px', opacity: 0.6 }} />
        <div style={{ background: '#1E293B', borderRadius: '6px', height: '14px', width: '180px', opacity: 0.4 }} />
      </div>
    )
  }

  return (
    <div style={{ padding: '28px 24px 20px', animation: 'slide-up 0.3s ease' }}>
      {/* Score ring */}
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', marginBottom: '24px' }}>
        <div style={{ position: 'relative', marginBottom: '16px' }}>
          {/* Glow effect */}
          <div style={{
            position: 'absolute', inset: '-12px',
            borderRadius: '50%',
            background: `radial-gradient(circle, ${risk.glow} 0%, transparent 70%)`,
            pointerEvents: 'none',
          }} />

          <svg width="128" height="128" viewBox="0 0 128 128" style={{ transform: 'rotate(-90deg)' }}>
            {/* Track */}
            <circle cx="64" cy="64" r={R} fill="none" stroke="#1E293B" strokeWidth="10" />
            {/* Gradient ring */}
            <defs>
              <linearGradient id="ring-gradient" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={risk.ring} stopOpacity="0.6" />
                <stop offset="100%" stopColor={risk.ring} />
              </linearGradient>
            </defs>
            <circle
              cx="64" cy="64" r={R}
              fill="none"
              stroke={`url(#ring-gradient)`}
              strokeWidth="10"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
              style={{ transition: 'stroke-dashoffset 0.1s linear' }}
            />
          </svg>

          {/* Center content */}
          <div style={{
            position: 'absolute', inset: 0,
            display: 'flex', flexDirection: 'column',
            alignItems: 'center', justifyContent: 'center', gap: '2px',
          }}>
            <span style={{ fontSize: '22px', lineHeight: 1 }}>{risk.emoji}</span>
            <span style={{ fontSize: '26px', fontWeight: 800, color: '#F1F5F9', lineHeight: 1, letterSpacing: '-1px' }}>
              {score !== null ? animatedScore : '—'}
            </span>
            <span style={{ fontSize: '10px', color: '#475569', fontWeight: 600 }}>/ 100</span>
          </div>
        </div>

        {/* Risk badge */}
        <div style={{
          display: 'inline-flex', alignItems: 'center', gap: '6px',
          background: risk.bg,
          border: `1px solid ${risk.color}44`,
          color: risk.color,
          padding: '5px 14px', borderRadius: '100px',
          fontSize: '11px', fontWeight: 800, letterSpacing: '1.5px',
          textTransform: 'uppercase',
        }}>
          {risk.label}
        </div>
      </div>

      {/* Domain */}
      <div style={{
        background: '#0F172A', border: '1px solid #1E293B',
        borderRadius: '12px', padding: '14px 16px', marginBottom: '14px',
      }}>
        <div style={{ color: '#475569', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px' }}>
          Current Site
        </div>
        <div style={{
          color: '#CBD5E1', fontSize: '13px', fontWeight: 500,
          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
        }}>
          {domain || 'No site detected'}
        </div>
      </div>

      {/* Status message */}
      <div style={{
        background: `${risk.bg}`,
        border: `1px solid ${risk.color}22`,
        borderRadius: '10px', padding: '12px 14px',
        color: '#94A3B8', fontSize: '12px', lineHeight: '1.6',
      }}>
        {risk.msg}
      </div>

      {!!explanation && score !== null && score >= 30 && (
        <div style={{
          marginTop: '14px',
          background: '#0F172A',
          border: `1px solid ${risk.color}22`,
          borderRadius: '10px',
          padding: '12px 14px',
        }}>
          <div style={{
            color: risk.color,
            fontSize: '10px',
            fontWeight: 700,
            textTransform: 'uppercase',
            letterSpacing: '1px',
            marginBottom: '6px',
          }}>
            Why It Was Flagged
          </div>
          <div style={{ color: '#CBD5E1', fontSize: '12px', lineHeight: '1.6' }}>
            {explanation}
          </div>
        </div>
      )}

      {/* Score breakdown if risky */}
      {score !== null && score >= 30 && (
        <div style={{ marginTop: '14px' }}>
          <div style={{ color: '#475569', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            Risk Breakdown
          </div>
          <div style={{ display: 'flex', gap: '4px', height: '6px', borderRadius: '100px', overflow: 'hidden', background: '#1E293B' }}>
            <div style={{ width: `${Math.min(score, 100)}%`, background: `linear-gradient(90deg, #22C55E, ${risk.ring})`, borderRadius: '100px', transition: 'width 0.8s ease' }} />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: '4px' }}>
            <span style={{ color: '#22C55E', fontSize: '10px' }}>Safe</span>
            <span style={{ color: '#EF4444', fontSize: '10px' }}>Critical</span>
          </div>
        </div>
      )}
    </div>
  )
}
