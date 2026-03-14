import type { EmailAnalysis, EmailSnapshot } from '../../types'

interface Props {
  analysis: EmailAnalysis | null
  snapshot: EmailSnapshot | null
  isProcessing: boolean
}

const LABEL_STYLES: Record<string, { badge: string; border: string; tone: string }> = {
  dangerous: { badge: '#dc2626', border: 'rgba(239,68,68,0.35)', tone: '#fecaca' },
  suspicious: { badge: '#ca8a04', border: 'rgba(234,179,8,0.35)', tone: '#fde68a' },
  safe: { badge: '#16a34a', border: 'rgba(34,197,94,0.35)', tone: '#bbf7d0' },
  processing: { badge: '#2563eb', border: 'rgba(59,130,246,0.35)', tone: '#bfdbfe' },
  error: { badge: '#7c3aed', border: 'rgba(139,92,246,0.35)', tone: '#ddd6fe' },
}

export function EmailGuard({ analysis, snapshot, isProcessing }: Props) {
  const state = isProcessing ? 'processing' : (analysis?.final_risk_label || 'safe')
  const style = LABEL_STYLES[state] || LABEL_STYLES.safe
  const scorePct = Math.min(100, Math.round((analysis?.final_score || 0) * 100))

  return (
    <div style={{ padding: '18px 16px 20px', animation: 'slide-up 0.25s ease' }}>
      <div style={{
        background: '#0D1421',
        border: `1px solid ${style.border}`,
        borderRadius: '16px',
        padding: '16px',
        marginBottom: '14px',
        boxShadow: `0 10px 32px ${style.border}`,
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
          <div>
            <div style={{ color: '#F8FAFC', fontSize: '15px', fontWeight: 800 }}>Email Phishing Guard</div>
            <div style={{ color: '#475569', fontSize: '11px', marginTop: '2px' }}>Integrated Gmail scanning in the same extension</div>
          </div>
          <div style={{
            background: style.badge,
            color: '#fff',
            borderRadius: '999px',
            padding: '6px 10px',
            fontSize: '10px',
            fontWeight: 800,
            textTransform: 'uppercase',
            letterSpacing: '0.8px',
          }}>
            {state}
          </div>
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1fr auto', gap: '12px', alignItems: 'center' }}>
          <div>
            <div style={{ color: '#64748B', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '5px' }}>
              Current Email
            </div>
            <div style={{ color: '#E2E8F0', fontSize: '13px', fontWeight: 600, marginBottom: '4px' }}>
              {snapshot?.subject || 'Open a Gmail message to analyze it'}
            </div>
            <div style={{ color: '#64748B', fontSize: '11px' }}>
              {snapshot?.fromEmail || snapshot?.from || 'No sender captured yet'}
            </div>
          </div>
          <div style={{ textAlign: 'right' }}>
            <div style={{ color: '#F8FAFC', fontSize: '28px', fontWeight: 800, lineHeight: 1 }}>{isProcessing ? '...' : `${scorePct}%`}</div>
            <div style={{ color: '#475569', fontSize: '10px', marginTop: '4px' }}>risk score</div>
          </div>
        </div>
      </div>

      <div style={{
        background: '#0A0F1A',
        border: '1px solid #172033',
        borderRadius: '14px',
        padding: '14px',
        marginBottom: '12px',
        color: '#CBD5E1',
        fontSize: '12px',
        lineHeight: '1.65',
      }}>
        {isProcessing
          ? 'Analyzing the currently open email...'
          : analysis?.explanation || 'No email analysis yet. Open Gmail, click an email, and this extension will score it here.'}
      </div>

      {analysis?.detected_patterns?.length ? (
        <div>
          <div style={{ color: '#64748B', fontSize: '10px', textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
            Detected Signals
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
            {analysis.detected_patterns.map((pattern) => (
              <span
                key={pattern}
                style={{
                  background: '#0D1421',
                  border: `1px solid ${style.border}`,
                  color: style.tone,
                  borderRadius: '999px',
                  padding: '5px 9px',
                  fontSize: '11px',
                }}
              >
                {pattern}
              </span>
            ))}
          </div>
        </div>
      ) : null}
    </div>
  )
}
