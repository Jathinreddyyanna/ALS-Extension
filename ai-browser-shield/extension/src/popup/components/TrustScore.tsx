import React, { useEffect, useState } from 'react'

interface Props {
  score: number | null
  domain: string
  isLoading?: boolean
  reportCount?: number
  onReport?: () => void
}

const RISK = {
  CRITICAL: {
    color: '#FF1744', bg: '#1A0505', ringBg: '#2D0505',
    banner: '#FF1744', bannerBg: 'rgba(255,23,68,0.12)',
    emoji: '🚨',
    headline: 'DANGER — Do Not Proceed',
    subline: 'This site shows signs of phishing or malware.',
    bullets: [
      'Do NOT enter your password or OTP',
      'Do NOT share your Aadhaar, PAN, or bank details',
      'Click "Go Back" to leave this page safely',
    ],
    action: 'Leave This Page',
  },
  HIGH: {
    color: '#FF6B00', bg: '#100800', ringBg: '#1E1000',
    banner: '#FF6B00', bannerBg: 'rgba(255,107,0,0.10)',
    emoji: '⚠️',
    headline: 'WARNING — Be Very Careful',
    subline: 'This site has suspicious characteristics.',
    bullets: [
      'Avoid entering any personal information',
      'Do not click "Allow" on any browser prompts',
      'Check the URL carefully before proceeding',
    ],
    action: 'Report This Site',
  },
  MEDIUM: {
    color: '#FFB300', bg: '#0C0900', ringBg: '#181200',
    banner: '#FFB300', bannerBg: 'rgba(255,179,0,0.08)',
    emoji: '🔶',
    headline: 'CAUTION — Unusual Patterns Found',
    subline: 'Proceed carefully and verify this site.',
    bullets: [
      'Verify the website address is correct',
      'Look for a padlock icon in the browser bar',
      'Avoid sharing sensitive information',
    ],
    action: 'Report If Suspicious',
  },
  LOW: {
    color: '#00C851', bg: '#040E08', ringBg: '#061408',
    banner: '#00C851', bannerBg: 'rgba(0,200,81,0.07)',
    emoji: '✅',
    headline: 'SAFE — No Threats Detected',
    subline: 'This site appears legitimate.',
    bullets: [
      'No phishing or malware signals found',
      'Domain reputation is clean',
      'Still use caution with personal information',
    ],
    action: 'Report If Suspicious',
  },
  UNKNOWN: {
    color: '#8899BB', bg: '#060B14', ringBg: '#0D1524',
    banner: '#8899BB', bannerBg: 'rgba(136,153,187,0.07)',
    emoji: '🔍',
    headline: 'Scanning...',
    subline: 'Checking this site for threats.',
    bullets: ['Analysis in progress...'],
    action: 'Report If Suspicious',
  },
}

function getRiskKey(score: number | null): keyof typeof RISK {
  if (score === null) return 'UNKNOWN'
  if (score >= 80) return 'CRITICAL'
  if (score >= 60) return 'HIGH'
  if (score >= 30) return 'MEDIUM'
  return 'LOW'
}

export function TrustScore({ score, domain, isLoading, reportCount = 0, onReport }: Props) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const riskKey = getRiskKey(score)
  const risk = RISK[riskKey]
  const R = 58
  const circumference = 2 * Math.PI * R
  const offset = circumference - (animatedScore / 100) * circumference

  useEffect(() => {
    if (score === null) {
      setAnimatedScore(0)
      return
    }
    const start = Date.now()
    const duration = 800
    const from = animatedScore
    const animate = () => {
      const elapsed = Date.now() - start
      const progress = Math.min(elapsed / duration, 1)
      const eased = 1 - Math.pow(1 - progress, 3)
      setAnimatedScore(Math.round(from + (score - from) * eased))
      if (progress < 1) requestAnimationFrame(animate)
    }
    requestAnimationFrame(animate)
  }, [score])

  if (isLoading) {
    return (
      <div style={{ padding: '40px 24px', display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '16px' }}>
        <div
          style={{
            width: '140px',
            height: '140px',
            borderRadius: '50%',
            background: '#0D1524',
            border: '10px solid #1A2740',
            opacity: 0.5,
          }}
        />
        <div style={{ background: '#0D1524', borderRadius: '8px', height: '22px', width: '160px' }} />
        <div style={{ background: '#0D1524', borderRadius: '6px', height: '14px', width: '220px', opacity: 0.6 }} />
        <div style={{ color: '#3D5070', fontSize: '12px' }}>Analysing site security...</div>
      </div>
    )
  }

  return (
    <div style={{ padding: '20px 20px 16px', animation: 'fade-in 0.3s ease' }}>
      <div
        style={{
          background: risk.bannerBg,
          border: `1.5px solid ${risk.banner}44`,
          borderRadius: '14px',
          padding: '14px 18px',
          marginBottom: '16px',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
        }}
      >
        <span style={{ fontSize: '32px', lineHeight: 1, flexShrink: 0 }}>{risk.emoji}</span>
        <div>
          <div
            style={{
              color: risk.color,
              fontSize: '15px',
              fontWeight: 900,
              letterSpacing: '-0.2px',
              lineHeight: 1.2,
            }}
          >
            {risk.headline}
          </div>
          <div style={{ color: '#8899BB', fontSize: '11px', marginTop: '3px' }}>{risk.subline}</div>
        </div>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', marginBottom: '16px' }}>
        <div style={{ position: 'relative', flexShrink: 0 }}>
          <svg width="140" height="140" viewBox="0 0 140 140" style={{ transform: 'rotate(-90deg)' }}>
            <circle cx="70" cy="70" r={R} fill="none" stroke={risk.ringBg} strokeWidth="12" />
            <defs>
              <linearGradient id="rg" x1="0%" y1="0%" x2="100%" y2="0%">
                <stop offset="0%" stopColor={risk.color} stopOpacity="0.5" />
                <stop offset="100%" stopColor={risk.color} />
              </linearGradient>
            </defs>
            <circle
              cx="70"
              cy="70"
              r={R}
              fill="none"
              stroke="url(#rg)"
              strokeWidth="12"
              strokeDasharray={circumference}
              strokeDashoffset={offset}
              strokeLinecap="round"
            />
          </svg>
          <div
            style={{
              position: 'absolute',
              inset: 0,
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
            }}
          >
            <span style={{ fontSize: '30px', fontWeight: 900, color: '#F0F4FF', lineHeight: 1, letterSpacing: '-2px' }}>
              {score !== null ? animatedScore : '—'}
            </span>
            <span style={{ fontSize: '11px', color: '#3D5070', fontWeight: 600 }}>/ 100</span>
          </div>
        </div>

        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ color: '#3D5070', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>
            Current Site
          </div>
          <div
            style={{
              color: '#F0F4FF',
              fontSize: '13px',
              fontWeight: 600,
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
              marginBottom: '8px',
            }}
          >
            {domain || 'No site active'}
          </div>

          <div style={{ height: '6px', background: '#1A2740', borderRadius: '100px', marginBottom: '4px', overflow: 'hidden' }}>
            <div
              style={{
                height: '100%',
                width: `${score ?? 0}%`,
                background: `linear-gradient(90deg, #00C851, ${risk.color})`,
                borderRadius: '100px',
                transition: 'width 0.8s ease',
              }}
            />
          </div>
          <div style={{ display: 'flex', justifyContent: 'space-between' }}>
            <span style={{ color: '#00C851', fontSize: '9px', fontWeight: 700 }}>SAFE</span>
            <span style={{ color: '#FF1744', fontSize: '9px', fontWeight: 700 }}>DANGER</span>
          </div>

          {reportCount > 0 && (
            <div
              style={{
                marginTop: '6px',
                display: 'inline-flex',
                alignItems: 'center',
                gap: '4px',
                background: 'rgba(255,107,0,0.1)',
                border: '1px solid rgba(255,107,0,0.2)',
                color: '#FF6B00',
                padding: '2px 8px',
                borderRadius: '6px',
                fontSize: '10px',
                fontWeight: 700,
              }}
            >
              👥 {reportCount} community reports
            </div>
          )}
        </div>
      </div>

      <div
        style={{
          background: '#0D1524',
          border: '1px solid #1A2740',
          borderRadius: '12px',
          padding: '14px 16px',
          marginBottom: '14px',
        }}
      >
        <div style={{ color: '#3D5070', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>
          What this means for you
        </div>
        {risk.bullets.map((bullet, i) => (
          <div key={i} style={{ display: 'flex', gap: '8px', alignItems: 'flex-start', marginBottom: i < risk.bullets.length - 1 ? '8px' : 0 }}>
            <div
              style={{
                width: '18px',
                height: '18px',
                borderRadius: '50%',
                flexShrink: 0,
                background: `${risk.color}20`,
                border: `1px solid ${risk.color}40`,
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontSize: '9px',
                color: risk.color,
                fontWeight: 900,
              }}
            >
              {i + 1}
            </div>
            <span style={{ color: '#8899BB', fontSize: '12px', lineHeight: '1.5' }}>{bullet}</span>
          </div>
        ))}
      </div>

      <div style={{ display: 'flex', gap: '8px' }}>
        {(riskKey === 'CRITICAL' || riskKey === 'HIGH') && (
          <button
            onClick={() => window.history.back()}
            style={{
              flex: 1,
              padding: '10px',
              background: `${risk.color}18`,
              border: `1.5px solid ${risk.color}44`,
              color: risk.color,
              borderRadius: '10px',
              cursor: 'pointer',
              fontSize: '12px',
              fontWeight: 700,
            }}
          >
            ← Go Back (Safe)
          </button>
        )}
        <button
          onClick={onReport}
          style={{
            flex: 1,
            padding: '10px',
            background: riskKey !== 'LOW' ? `${risk.color}12` : '#0D1524',
            border: `1px solid ${riskKey !== 'LOW' ? `${risk.color}30` : '#1A2740'}`,
            color: riskKey !== 'LOW' ? risk.color : '#3D5070',
            borderRadius: '10px',
            cursor: 'pointer',
            fontSize: '12px',
            fontWeight: 600,
          }}
        >
          🚩 {risk.action}
        </button>
      </div>
    </div>
  )
}
