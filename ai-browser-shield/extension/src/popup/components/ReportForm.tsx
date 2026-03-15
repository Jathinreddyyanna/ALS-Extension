import React, { useState } from 'react'

interface Props {
  onSubmit: (data: { category: string; description: string }) => void
  success: boolean
  domain: string
}

const CATEGORIES = [
  { value: 'phishing', emoji: '🎣', label: 'Fake Login', desc: 'Pretends to be a bank, UPI, or government login page' },
  { value: 'scam', emoji: '💸', label: 'Scam Offer', desc: 'Fake prizes, free recharge, loan, or money offer' },
  { value: 'malware', emoji: '🦠', label: 'Malware', desc: 'Tries to download or install harmful files' },
  { value: 'redirect', emoji: '🔁', label: 'Redirects', desc: 'Keeps bouncing to other websites' },
  { value: 'popup_abuse', emoji: '🪟', label: 'Popups', desc: 'Shows too many popups or fake alerts' },
  { value: 'other', emoji: '⚠️', label: 'Other', desc: 'Anything else that feels suspicious' },
]

export function ReportForm({ onSubmit, success, domain }: Props) {
  const [category, setCategory] = useState('')
  const [description, setDescription] = useState('')
  const [focused, setFocused] = useState(false)

  if (success) {
    return (
      <div style={{ padding: '56px 24px', textAlign: 'center' }}>
        <div
          style={{
            width: '76px',
            height: '76px',
            margin: '0 auto 20px',
            background: 'linear-gradient(135deg, #004d1f, #00C851)',
            border: '2px solid rgba(0,200,81,0.35)',
            borderRadius: '50%',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '36px',
            boxShadow: '0 0 32px rgba(0,200,81,0.25)',
          }}
        >
          ✅
        </div>
        <div style={{ color: '#00C851', fontSize: '20px', fontWeight: 900, marginBottom: '8px' }}>
          Report Sent!
        </div>
        <div style={{ color: '#8899BB', fontSize: '13px', lineHeight: '1.7' }}>
          Thank you. Your report helps warn other people
          <br />
          before they visit this site.
        </div>
      </div>
    )
  }

  const canSubmit = !!category

  return (
    <div style={{ padding: '16px' }}>
      {domain && (
        <div
          style={{
            background: '#0D1524',
            border: '1px solid #1A2740',
            borderRadius: '12px',
            padding: '11px 14px',
            marginBottom: '14px',
          }}
        >
          <div style={{ color: '#3D5070', fontSize: '10px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>
            Reporting this site
          </div>
          <div style={{ color: '#F0F4FF', fontSize: '13px', fontWeight: 600, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {domain}
          </div>
        </div>
      )}

      <div
        style={{
          background: 'rgba(59,130,246,0.07)',
          border: '1px solid rgba(59,130,246,0.15)',
          borderRadius: '12px',
          padding: '12px 14px',
          marginBottom: '16px',
        }}
      >
        <div style={{ color: '#60A5FA', fontSize: '12px', fontWeight: 700, marginBottom: '4px' }}>
          Help protect everyone 🛡️
        </div>
        <div style={{ color: '#3D5070', fontSize: '11px', lineHeight: '1.5' }}>
          Your report helps warn other users before they visit this site.
          It only takes 10 seconds.
        </div>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <div style={{ color: '#8899BB', fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '10px' }}>
          What looks wrong?
        </div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
          {CATEGORIES.map((cat) => {
            const isSelected = category === cat.value
            return (
              <button
                key={cat.value}
                onClick={() => setCategory(cat.value)}
                style={{
                  background: isSelected ? 'rgba(37,99,235,0.14)' : '#0D1524',
                  border: `1px solid ${isSelected ? 'rgba(96,165,250,0.35)' : '#1A2740'}`,
                  borderRadius: '12px',
                  padding: '12px',
                  cursor: 'pointer',
                  textAlign: 'left',
                  display: 'flex',
                  alignItems: 'flex-start',
                  gap: '9px',
                }}
              >
                <span style={{ fontSize: '18px', lineHeight: 1 }}>{cat.emoji}</span>
                <div>
                  <div style={{ color: isSelected ? '#93C5FD' : '#F0F4FF', fontSize: '12px', fontWeight: 800 }}>
                    {cat.label}
                  </div>
                  <div style={{ color: '#8899BB', fontSize: '10px', lineHeight: '1.45', marginTop: '3px' }}>
                    {cat.desc}
                  </div>
                </div>
              </button>
            )
          })}
        </div>
      </div>

      <div style={{ marginBottom: '16px' }}>
        <div style={{ color: '#8899BB', fontSize: '11px', fontWeight: 800, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '8px' }}>
          Extra details (optional)
        </div>
        <textarea
          value={description}
          onChange={(e) => setDescription(e.target.value)}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder="Example: It asked for my bank OTP, or showed a fake update message..."
          maxLength={500}
          style={{
            width: '100%',
            background: '#0D1524',
            border: `1px solid ${focused ? 'rgba(96,165,250,0.35)' : '#1A2740'}`,
            borderRadius: '12px',
            color: '#F0F4FF',
            fontSize: '13px',
            padding: '12px 14px',
            resize: 'none',
            height: '88px',
            outline: 'none',
            fontFamily: 'inherit',
            lineHeight: '1.5',
          }}
        />
        <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: '5px' }}>
          <span style={{ color: description.length > 400 ? '#FF6B00' : '#3D5070', fontSize: '10px' }}>
            {description.length}/500
          </span>
        </div>
      </div>

      <button
        disabled={!canSubmit}
        onClick={() => canSubmit && onSubmit({ category, description })}
        style={{
          width: '100%',
          padding: '14px',
          background: canSubmit ? 'linear-gradient(135deg, #1D4ED8, #2563EB)' : '#0D1524',
          border: canSubmit ? 'none' : '1px solid #1A2740',
          color: canSubmit ? '#fff' : '#3D5070',
          borderRadius: '12px',
          cursor: canSubmit ? 'pointer' : 'not-allowed',
          fontSize: '14px',
          fontWeight: 700,
          transition: 'all 0.15s ease',
        }}
      >
        {canSubmit ? '🚩 Submit Report' : 'Select a category to continue'}
      </button>
    </div>
  )
}
