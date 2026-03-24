import React, { useEffect, useMemo, useState } from 'react'
import { useStore } from '../store'
import { DEMO_EMAILS } from '../demoEmails'

function getScoreColor(score: number): string {
  if (score >= 81) return '#EF4444'
  if (score >= 56) return '#F97316'
  if (score >= 26) return '#EAB308'
  return '#22C55E'
}

function getLabel(score: number): string {
  if (score >= 81) return 'CRITICAL'
  if (score >= 56) return 'HIGH'
  if (score >= 26) return 'SUSPICIOUS'
  return 'SAFE'
}

export function EmailAnalyser() {
  const emailText = useStore((s) => s.emailText)
  const emailRiskScore = useStore((s) => s.emailRiskScore)
  const emailStatus = useStore((s) => s.emailStatus)
  const emailExplanation = useStore((s) => s.emailExplanation)
  const emailAttackType = useStore((s) => s.emailAttackType)
  const emailConfidence = useStore((s) => s.emailConfidence)
  const emailIsSpamFolder = useStore((s) => s.emailIsSpamFolder)
  const emailSignals = useStore((s) => s.emailSignals)
  const emailDetectedPatterns = useStore((s) => s.emailDetectedPatterns)

  const [draftText, setDraftText] = useState('')
  const [selectedDemoTitle, setSelectedDemoTitle] = useState('')

  const selectedDemo = useMemo(
    () => DEMO_EMAILS.find((demo) => demo.title === selectedDemoTitle),
    [selectedDemoTitle],
  )

  useEffect(() => {
    if (emailText?.trim()) {
      setDraftText(emailText)
      setSelectedDemoTitle('')
    }
  }, [emailText])

  const filteredSignals = useMemo(
    () => emailSignals.filter((signal) => signal.score > 0),
    [emailSignals],
  )

  const clampedConfidence = Math.max(0, Math.min(100, Math.round(emailConfidence)))
  const hasResult = emailStatus === 'ready' || filteredSignals.length > 0 || !!emailExplanation

  const color = getScoreColor(emailRiskScore)

  const analyzeEmail = () => {
    const text = draftText.trim()
    if (text.length < 20) return

    chrome.runtime.sendMessage({
      type: 'EMAIL_CONTENT',
      payload: {
        emailText: text,
        senderEmail: '',
        isSpamFolder: false,
      },
    }).catch(() => {})
  }

  return (
    <div style={{ padding: '16px', color: '#E2E8F0' }}>
      <div style={{ marginBottom: '10px', display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
        {DEMO_EMAILS.map((demo) => {
          const selected = selectedDemoTitle === demo.title
          return (
            <button
              key={demo.title}
              onClick={() => {
                setDraftText(demo.content)
                setSelectedDemoTitle(demo.title)
              }}
              style={{
                border: selected ? '1px solid #3B82F6' : '1px solid #1E3A5F',
                background: selected ? 'rgba(59,130,246,0.2)' : '#0B1220',
                color: selected ? '#BFDBFE' : '#93C5FD',
                borderRadius: '7px',
                padding: '4px 8px',
                cursor: 'pointer',
                fontSize: '11px',
                fontWeight: 600,
                lineHeight: 1.2,
              }}
            >
              {demo.title}
            </button>
          )
        })}
      </div>

      {selectedDemo && (
        <div style={{
          marginBottom: '10px',
          border: '1px solid #1E3A5F',
          borderRadius: '8px',
          background: '#0B1220',
          padding: '8px 10px',
          fontSize: '11px',
          color: '#93C5FD',
        }}>
          Expected: <strong style={{ color: '#E2E8F0' }}>{(selectedDemo as any).expected || 'Demo scenario'}</strong>
        </div>
      )}

      <div style={{
        background: '#0B1220',
        border: '1px solid #1E3A5F',
        borderRadius: '10px',
        padding: '10px',
        marginBottom: '10px',
      }}>
        <textarea
          value={draftText}
          onChange={(e) => {
            setDraftText(e.target.value)
            setSelectedDemoTitle('')
          }}
          placeholder='Open a Gmail email or paste suspicious email text here...'
          rows={5}
          style={{
            width: '100%',
            resize: 'vertical',
            background: '#0A1020',
            color: '#E2E8F0',
            border: '1px solid #1E3A5F',
            borderRadius: '8px',
            padding: '8px 10px',
            fontSize: '12px',
            lineHeight: 1.45,
            boxSizing: 'border-box',
          }}
        />
        <button
          onClick={analyzeEmail}
          disabled={draftText.trim().length < 20 || emailStatus === 'analyzing'}
          style={{
            marginTop: '10px',
            width: '100%',
            border: '1px solid #3B82F6',
            background: emailStatus === 'analyzing' ? '#1E3A8A' : '#1D4ED8',
            color: '#E2E8F0',
            borderRadius: '8px',
            padding: '8px 10px',
            fontSize: '13px',
            fontWeight: 700,
            cursor: draftText.trim().length < 20 || emailStatus === 'analyzing' ? 'not-allowed' : 'pointer',
            opacity: draftText.trim().length < 20 ? 0.6 : 1,
          }}
        >
          {emailStatus === 'analyzing' ? 'Analyzing...' : 'Analyse Email'}
        </button>
      </div>

      {emailStatus === 'waiting' && !hasResult && (
        <div style={{
          background: '#0D1421',
          border: '1px solid #1E3A5F',
          borderRadius: '10px',
          padding: '12px',
          color: '#93C5FD',
          fontSize: '12px',
          fontWeight: 600,
          marginBottom: '10px',
        }}>
          Waiting for email to open...
        </div>
      )}

      <div style={{
        background: '#0D1421',
        border: `1px solid ${color}55`,
        borderTop: `3px solid ${color}`,
        borderRadius: '10px',
        padding: '14px',
      }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <div style={{
            background: `${color}22`,
            border: `1px solid ${color}44`,
            color,
            padding: '4px 10px',
            borderRadius: '6px',
            fontSize: '11px',
            fontWeight: 800,
            letterSpacing: '0.4px',
          }}>
            {getLabel(emailRiskScore)}
          </div>
          <div style={{ color, fontSize: '24px', fontWeight: 800 }}>
            {emailRiskScore}
            <span style={{ fontSize: '12px', color: '#334155' }}>/100</span>
          </div>
        </div>

        <div style={{
          color: '#94A3B8',
          fontSize: '12px',
          lineHeight: 1.55,
          borderLeft: `2px solid ${color}`,
          paddingLeft: '8px',
          marginBottom: '10px',
        }}>
          {emailExplanation || 'Local phishing analysis completed.'}
        </div>

        <div style={{
          marginTop: '10px',
          background: '#0B1220',
          border: '1px solid #1E3A5F',
          borderRadius: '8px',
          padding: '10px',
        }}>
          <div style={{ fontSize: '10px', color: '#64748B', marginBottom: '6px', fontWeight: 700, letterSpacing: '0.3px' }}>
            EXTRACTED EMAIL TEXT
          </div>
          <div style={{
            maxHeight: '130px',
            overflowY: 'auto',
            whiteSpace: 'pre-wrap',
            fontSize: '12px',
            lineHeight: 1.45,
            color: '#E2E8F0',
          }}>
            {emailText || draftText || 'No email content available yet.'}
          </div>
        </div>

        <div style={{ marginTop: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <span style={{ fontSize: '10px', color: '#64748B', fontWeight: 700, letterSpacing: '0.3px' }}>
              ANALYSIS CONFIDENCE
            </span>
            <span style={{ fontSize: '11px', color, fontWeight: 700 }}>
              {clampedConfidence}%
            </span>
          </div>
          <div style={{ width: '100%', height: '5px', background: '#1E293B', borderRadius: '3px', overflow: 'hidden' }}>
            <div style={{ width: `${clampedConfidence}%`, height: '100%', background: color }} />
          </div>
        </div>

        {emailIsSpamFolder && (
          <div style={{
            marginTop: '10px',
            background: 'rgba(239,68,68,0.12)',
            border: '1px solid rgba(239,68,68,0.35)',
            color: '#FCA5A5',
            borderRadius: '8px',
            padding: '8px 10px',
            fontSize: '11px',
            fontWeight: 600,
          }}>
            ⚠ Gmail marked this message as spam.
          </div>
        )}

        {emailAttackType && emailAttackType !== 'None' && (
          <div style={{
            marginTop: '10px',
            background: 'rgba(59,130,246,0.12)',
            border: '1px solid rgba(59,130,246,0.35)',
            color: '#93C5FD',
            borderRadius: '8px',
            padding: '8px 10px',
            fontSize: '11px',
            fontWeight: 600,
          }}>
            Warning: {emailAttackType}
          </div>
        )}

        {emailDetectedPatterns.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '10px', color: '#64748B', marginBottom: '6px', fontWeight: 700, letterSpacing: '0.3px' }}>
              PSYCHOLOGICAL TRIGGERS DETECTED
            </div>
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: '6px' }}>
              {emailDetectedPatterns.slice(0, 8).map((pattern, idx) => (
                <div key={`${pattern}-${idx}`} style={{
                  border: '1px solid rgba(239,68,68,0.35)',
                  background: 'rgba(239,68,68,0.12)',
                  color: '#FCA5A5',
                  borderRadius: '6px',
                  padding: '3px 8px',
                  fontSize: '10px',
                  fontWeight: 700,
                }}>
                  {pattern}
                </div>
              ))}
            </div>
          </div>
        )}

        {filteredSignals.length > 0 && (
          <div style={{ marginTop: '12px' }}>
            <div style={{ fontSize: '10px', color: '#64748B', marginBottom: '6px', fontWeight: 700, letterSpacing: '0.3px' }}>
              PHISHING SIGNALS DETECTED
            </div>
            <div style={{
              background: '#0B1220',
              border: '1px solid #1E3A5F',
              borderRadius: '8px',
              padding: '8px 10px',
            }}>
              {filteredSignals.map((signal, idx, arr) => (
                <div key={`${signal.name}-${idx}`} style={{
                  fontSize: '11px',
                  color: '#CBD5E1',
                  lineHeight: 1.45,
                  marginBottom: idx < arr.length - 1 ? '4px' : '0',
                }}>
                  • <strong>{signal.name}</strong>: <span style={{ color }}>+{signal.score}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
