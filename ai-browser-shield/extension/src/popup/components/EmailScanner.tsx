import React from 'react'
import type { EmailAnalysis } from '../../types'

interface Props {
  analysis: EmailAnalysis | null
}

const LABEL_STYLES = {
  dangerous: { bg: '#450A0A', border: '#EF4444', text: '#FCA5A5', title: 'Dangerous' },
  suspicious: { bg: '#422006', border: '#EAB308', text: '#FDE68A', title: 'Suspicious' },
  safe: { bg: '#052E16', border: '#22C55E', text: '#86EFAC', title: 'Safe' },
  processing: { bg: '#1E293B', border: '#60A5FA', text: '#BFDBFE', title: 'Analyzing' },
  error: { bg: '#431407', border: '#F97316', text: '#FED7AA', title: 'Error' },
} as const

export function EmailScanner({ analysis }: Props) {
  if (!analysis) {
    return (
      <div style={{ padding: '44px 24px', textAlign: 'center' }}>
        <div style={{ fontSize: '44px', marginBottom: '12px' }}>📨</div>
        <div style={{ color: '#E2E8F0', fontSize: '16px', fontWeight: 700, marginBottom: '6px' }}>No email or chat analyzed yet</div>
        <div style={{ color: '#475569', fontSize: '13px', lineHeight: '1.6' }}>
          Open Gmail, WhatsApp Web, or Telegram Web and this tab will show the latest analysis.
        </div>
      </div>
    )
  }

  const style = LABEL_STYLES[analysis.riskLabel]
  const score = Math.round((analysis.finalScore || 0) * 100)

  return (
    <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
      <div style={{
        background: style.bg,
        border: `1px solid ${style.border}55`,
        borderRadius: '14px',
        padding: '14px 16px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
          <div style={{ color: style.text, fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px' }}>
            {style.title}
          </div>
          <div style={{ color: style.text, fontSize: '22px', fontWeight: 800 }}>
            {score}%
          </div>
        </div>
        <div style={{ color: '#CBD5E1', fontSize: '13px', fontWeight: 600, marginBottom: '4px' }}>
          {analysis.subject || '(No subject)'}
        </div>
        <div style={{ color: '#64748B', fontSize: '11px' }}>
          {analysis.platform.toUpperCase()} • {analysis.from}
        </div>
      </div>

      <div style={{
        background: '#0F172A',
        border: '1px solid #1E293B',
        borderRadius: '12px',
        padding: '12px 14px',
      }}>
        <div style={{ color: '#475569', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '6px' }}>
          Why It Was Flagged
        </div>
        <div style={{ color: '#CBD5E1', fontSize: '12px', lineHeight: '1.6' }}>
          {analysis.explanation}
        </div>
      </div>

      {analysis.detectedPatterns.length > 0 && (
        <div style={{
          background: '#0F172A',
          border: '1px solid #1E293B',
          borderRadius: '12px',
          padding: '12px 14px',
        }}>
          <div style={{ color: '#475569', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            Detected Signals
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {analysis.detectedPatterns.map(pattern => (
              <span key={pattern} style={{
                background: `${style.border}22`,
                border: `1px solid ${style.border}44`,
                color: style.text,
                borderRadius: '999px',
                padding: '4px 8px',
                fontSize: '11px',
                fontWeight: 600,
              }}>
                {pattern}
              </span>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}
