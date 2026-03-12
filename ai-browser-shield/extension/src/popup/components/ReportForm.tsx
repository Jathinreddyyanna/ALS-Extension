import React, { useState } from 'react'

interface Props {
  onSubmit: (data: { category: string; description: string }) => void
  success: boolean
  domain: string
}

const CATEGORIES = [
  { value: 'phishing',    emoji: '🎣', label: 'Phishing',     desc: 'Fake login page stealing credentials' },
  { value: 'scam',        emoji: '💸', label: 'Scam',          desc: 'Fraudulent offers or fake stores' },
  { value: 'malware',     emoji: '🦠', label: 'Malware',       desc: 'Distributes malicious software' },
  { value: 'redirect',    emoji: '🔄', label: 'Redirect Chain',desc: 'Suspicious redirect sequences' },
  { value: 'popup_abuse', emoji: '🪟', label: 'Popup Abuse',   desc: 'Aggressive popup spam' },
  { value: 'other',       emoji: '⚠️', label: 'Other',         desc: 'Other suspicious behaviour' },
]

export function ReportForm({ onSubmit, success, domain }: Props) {
  const [category, setCategory] = useState('')
  const [description, setDescription] = useState('')
  const [focused, setFocused] = useState(false)

  if (success) {
    return (
      <div style={{ padding: '60px 24px', textAlign: 'center', animation: 'slide-up 0.4s ease' }}>
        <div style={{
          width: '72px', height: '72px', margin: '0 auto 20px',
          background: 'linear-gradient(135deg, #052E16, #166534)',
          border: '2px solid #22C55E44',
          borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: '36px',
          boxShadow: '0 0 32px rgba(34,197,94,0.3)',
        }}>✅</div>
        <div style={{ color: '#22C55E', fontSize: '18px', fontWeight: 800, marginBottom: '8px' }}>
          Report Submitted!
        </div>
        <div style={{ color: '#475569', fontSize: '13px', lineHeight: '1.6' }}>
          Thank you for helping protect the community.<br />Our team will review this site.
        </div>
      </div>
    )
  }

  const canSubmit = !!category

  return (
    <div style={{ padding: '16px', animation: 'slide-up 0.25s ease' }}>
      {/* Domain being reported */}
      {domain && (
        <div style={{
          background: '#0D1421', border: '1px solid #1E293B',
          borderRadius: '10px', padding: '10px 14px', marginBottom: '16px',
          display: 'flex', alignItems: 'center', gap: '8px',
        }}>
          <span style={{ fontSize: '14px' }}>🔗</span>
          <div style={{ minWidth: 0 }}>
            <div style={{ color: '#475569', fontSize: '10px', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '1px' }}>Reporting</div>
            <div style={{ color: '#CBD5E1', fontSize: '12px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{domain}</div>
          </div>
        </div>
      )}

      {/* Category selection */}
      <div style={{ marginBottom: '14px' }}>
        <div style={{ color: '#64748B', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
          Threat Type *
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px' }}>
          {CATEGORIES.map(cat => {
            const isSelected = category === cat.value
            return (
              <button key={cat.value} onClick={() => setCategory(cat.value)} style={{
                background: isSelected ? 'rgba(59,130,246,0.15)' : '#0D1421',
                border: `1px solid ${isSelected ? 'rgba(59,130,246,0.5)' : '#1E293B'}`,
                borderRadius: '10px', padding: '10px 12px',
                cursor: 'pointer', textAlign: 'left',
                transition: 'all 0.15s ease',
                display: 'flex', alignItems: 'flex-start', gap: '8px',
              }}>
                <span style={{ fontSize: '18px', lineHeight: 1, marginTop: '1px' }}>{cat.emoji}</span>
                <div>
                  <div style={{ color: isSelected ? '#93C5FD' : '#CBD5E1', fontSize: '12px', fontWeight: 700 }}>{cat.label}</div>
                  <div style={{ color: '#475569', fontSize: '10px', lineHeight: '1.4', marginTop: '2px' }}>{cat.desc}</div>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      {/* Description */}
      <div style={{ marginBottom: '16px' }}>
        <div style={{ color: '#64748B', fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
          Description <span style={{ fontWeight: 400, textTransform: 'none', letterSpacing: 0 }}>(optional)</span>
        </div>
        <textarea
          value={description}
          onChange={e => setDescription(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder="Describe what you noticed (fake login, unexpected redirect, etc.)..."
          maxLength={500}
          style={{
            width: '100%', background: '#0D1421',
            border: `1px solid ${focused ? 'rgba(59,130,246,0.5)' : '#1E293B'}`,
            borderRadius: '10px', color: '#E2E8F0', fontSize: '13px',
            padding: '10px 12px', resize: 'none', height: '80px',
            outline: 'none', fontFamily: 'inherit', lineHeight: '1.5',
            transition: 'border-color 0.15s ease',
          }}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '3px' }}>
          <span style={{ color: description.length > 400 ? '#F97316' : '#334155', fontSize: '10px' }}>
            {description.length}/500
          </span>
        </div>
      </div>

      {/* Submit */}
      <button
        disabled={!canSubmit}
        onClick={() => canSubmit && onSubmit({ category, description })}
        style={{
          width: '100%',
          background: canSubmit
            ? 'linear-gradient(135deg, #1D4ED8, #2563EB)'
            : '#0D1421',
          color: canSubmit ? '#DBEAFE' : '#334155',
          border: `1px solid ${canSubmit ? 'rgba(59,130,246,0.4)' : '#1E293B'}`,
          borderRadius: '12px', padding: '13px',
          fontSize: '14px', fontWeight: 700,
          cursor: canSubmit ? 'pointer' : 'not-allowed',
          transition: 'all 0.2s ease',
          boxShadow: canSubmit ? '0 4px 16px rgba(29,78,216,0.35)' : 'none',
        }}
      >
        🚩 Submit Report
      </button>

      <div style={{ textAlign: 'center', marginTop: '10px', color: '#334155', fontSize: '11px' }}>
        Reports are anonymous and reviewed by our team
      </div>
    </div>
  )
}
