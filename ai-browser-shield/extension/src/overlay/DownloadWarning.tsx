import React, { useState, useEffect } from 'react'

interface Props {
  filename: string
  extension: string
  riskLevel: 'high' | 'medium'
  reason: string
  sourceUrl: string
  downloadId: number
  onCancel: () => void
  onProceed: () => void
  onScanFile?: () => void
}

const RISK_CONFIG = {
  high: {
    bg: 'linear-gradient(145deg, rgba(20,8,8,0.97), rgba(12,5,5,0.99))',
    border: 'rgba(239,68,68,0.4)',
    accent: '#EF4444',
    accentBg: 'rgba(239,68,68,0.1)',
    badge: 'linear-gradient(135deg, #7F1D1D, #991B1B)',
    badgeText: '#FCA5A5',
    badgeLabel: '🚨 HIGH RISK',
    title: 'Dangerous Download Blocked',
    icon: '🚫',
    glow: 'rgba(127,29,29,0.3)',
  },
  medium: {
    bg: 'linear-gradient(145deg, rgba(18,12,3,0.97), rgba(12,8,2,0.99))',
    border: 'rgba(234,179,8,0.35)',
    accent: '#EAB308',
    accentBg: 'rgba(234,179,8,0.1)',
    badge: 'linear-gradient(135deg, #713F12, #92400E)',
    badgeText: '#FEF08A',
    badgeLabel: '⚠️ SUSPICIOUS',
    title: 'Suspicious Download Detected',
    icon: '⚠️',
    glow: 'rgba(113,63,18,0.3)',
  },
}

const EXT_ICONS: Record<string, string> = {
  '.exe': '⚙️', '.msi': '⚙️', '.bat': '💾', '.cmd': '💾',
  '.ps1': '📋', '.vbs': '📋', '.js': '📜', '.jar': '☕',
  '.zip': '📦', '.rar': '📦', '.7z': '📦',
  '.dmg': '💿', '.pkg': '📦', '.apk': '📱',
  '.pdf': '📄', '.doc': '📄', '.xls': '📊',
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1048576) return `${(bytes/1024).toFixed(1)} KB`
  return `${(bytes/1048576).toFixed(1)} MB`
}

export function DownloadWarning({ filename, extension, riskLevel, reason, sourceUrl, downloadId, onCancel, onProceed, onScanFile }: Props) {
  const [visible, setVisible] = useState(false)
  const cfg = RISK_CONFIG[riskLevel]
  const fileIcon = EXT_ICONS[extension.toLowerCase()] || '📁'
  const sourceDomain = (() => { try { return new URL(sourceUrl).hostname } catch { return sourceUrl } })()

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))
  }, [])

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 2147483647,
      fontFamily: '-apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif',
      background: `radial-gradient(ellipse at center, ${cfg.glow} 0%, rgba(0,0,0,0.88) 60%)`,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      backdropFilter: 'blur(4px)',
      opacity: visible ? 1 : 0,
      transition: 'opacity 0.3s ease',
    }}>
      <div style={{
        background: cfg.bg,
        border: `1px solid ${cfg.border}`,
        borderRadius: '20px', padding: '36px 32px',
        maxWidth: '460px', width: '90%',
        boxShadow: `0 0 0 1px ${cfg.accentBg}, 0 32px 64px rgba(0,0,0,0.9)`,
        transform: visible ? 'scale(1) translateY(0)' : 'scale(0.92) translateY(24px)',
        transition: 'transform 0.35s cubic-bezier(0.34, 1.3, 0.64, 1)',
      }}>
        {/* Header */}
        <div style={{ textAlign: 'center', marginBottom: '24px' }}>
          <div style={{ fontSize: '48px', marginBottom: '12px', lineHeight: 1 }}>{cfg.icon}</div>
          <span style={{
            display: 'inline-block',
            background: cfg.badge, color: cfg.badgeText,
            fontSize: '10px', fontWeight: 800, padding: '4px 14px',
            borderRadius: '100px', letterSpacing: '1.5px',
            textTransform: 'uppercase', marginBottom: '10px',
          }}>{cfg.badgeLabel}</span>
          <h2 style={{
            color: '#F9FAFB', fontSize: '20px', fontWeight: 700,
            margin: 0, letterSpacing: '-0.01em',
          }}>{cfg.title}</h2>
        </div>

        {/* File card */}
        <div style={{
          background: 'rgba(255,255,255,0.04)', border: `1px solid ${cfg.border}`,
          borderRadius: '14px', padding: '16px', marginBottom: '16px',
          display: 'flex', alignItems: 'center', gap: '14px',
        }}>
          <div style={{
            width: '48px', height: '48px', flexShrink: 0,
            background: cfg.accentBg, border: `1px solid ${cfg.border}`,
            borderRadius: '12px', display: 'flex', alignItems: 'center',
            justifyContent: 'center', fontSize: '24px',
          }}>{fileIcon}</div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{
              color: '#F9FAFB', fontSize: '14px', fontWeight: 600,
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              marginBottom: '4px',
            }}>{filename}</div>
            <div style={{ display: 'flex', gap: '8px', alignItems: 'center' }}>
              <span style={{
                background: cfg.accentBg, color: cfg.accent,
                fontSize: '10px', fontWeight: 700, padding: '2px 8px',
                borderRadius: '5px', textTransform: 'uppercase',
              }}>{extension}</span>
              <span style={{ color: '#6B7280', fontSize: '11px' }}>from {sourceDomain}</span>
            </div>
          </div>
        </div>

        {/* Reason */}
        <div style={{
          background: cfg.accentBg, border: `1px solid ${cfg.border}`,
          borderRadius: '12px', padding: '14px 16px', marginBottom: '20px',
          display: 'flex', gap: '10px',
        }}>
          <span style={{ fontSize: '16px', flexShrink: 0 }}>🔍</span>
          <div>
            <div style={{ color: cfg.accent, fontSize: '11px', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '1px', marginBottom: '4px' }}>
              Why This Was Flagged
            </div>
            <div style={{ color: '#D1D5DB', fontSize: '13px', lineHeight: '1.6' }}>{reason}</div>
          </div>
        </div>

        {/* Action buttons */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
          <button onClick={onCancel} style={{
            background: 'linear-gradient(135deg, #166534, #15803D)',
            color: '#D1FAE5', border: 'none', padding: '13px',
            borderRadius: '12px', fontSize: '14px', fontWeight: 700,
            cursor: 'pointer', boxShadow: '0 4px 16px rgba(22,101,52,0.35)',
            transition: 'all 0.15s ease', width: '100%',
          }}>
            🛡️ {riskLevel === 'high' ? 'Delete & Stay Safe' : 'Cancel Download'}
          </button>

          {onScanFile && (
            <button onClick={onScanFile} style={{
              background: 'rgba(59,130,246,0.12)', color: '#93C5FD',
              border: '1px solid rgba(59,130,246,0.25)', padding: '11px',
              borderRadius: '12px', fontSize: '13px', fontWeight: 600,
              cursor: 'pointer', transition: 'all 0.15s ease', width: '100%',
            }}>
              🤖 Scan with AI First
            </button>
          )}

          <button onClick={onProceed} style={{
            background: 'transparent', color: '#4B5563',
            border: '1px solid rgba(255,255,255,0.06)', padding: '10px',
            borderRadius: '10px', fontSize: '12px',
            cursor: 'pointer', transition: 'all 0.15s ease', width: '100%',
          }}>
            I understand the risk — download anyway
          </button>
        </div>

        {/* Footer */}
        <div style={{ textAlign: 'center', marginTop: '16px' }}>
          <span style={{ color: '#374151', fontSize: '11px' }}>🛡️ AI Browser Shield • Download Protection</span>
        </div>
      </div>
    </div>
  )
}
