import { useEffect, useRef, useState } from 'react'
import { useVaultStore } from '../../store/useVaultStore'

export const VaultDashboardTab = () => {
  const { audit, fetchAudit, exportVault, importVault, error } = useVaultStore()
  const [message, setMessage] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  useEffect(() => {
    void fetchAudit()
  }, [fetchAudit])

  const score = audit?.overallScore ?? 0
  const scoreColor = score >= 80 ? '#0D9B6A' : score >= 50 ? '#F59E0B' : '#EF4444'
  const issues = [
    audit && audit.weakPasswords.length > 0 ? `${audit.weakPasswords.length} passwords are weak` : null,
    audit && audit.reusedPasswords.length > 0 ? `${audit.reusedPasswords.length} passwords are reused` : null,
    audit && audit.oldPasswords.length > 0 ? `${audit.oldPasswords.length} passwords are older than 90 days` : null,
  ].filter(Boolean) as string[]

  const handleImport = async (file?: File) => {
    if (!file) return
    await importVault(file)
    setMessage('Vault imported. Unlock with the source master password.')
    window.setTimeout(() => setMessage(null), 2500)
  }

  return (
    <div className="space-y-4">
      <div className="surface-card flex flex-col items-center gap-3 p-4 text-center">
        <svg viewBox="0 0 120 120" className="h-36 w-36">
          <circle r="52" cx="60" cy="60" fill="none" stroke="var(--surface-alt)" strokeWidth="14" />
          <circle
            r="52"
            cx="60"
            cy="60"
            fill="none"
            stroke={scoreColor}
            strokeWidth="14"
            strokeDasharray={`${(score / 100) * 327} 327`}
            strokeLinecap="round"
            transform="rotate(-90 60 60)"
          />
          <text x="60" y="64" textAnchor="middle" fontSize="24" fill={scoreColor}>{score}</text>
        </svg>
        <p className="subheading">Security Score</p>
        <p className="caption">Add passwords to see your security health.</p>
      </div>

      <div className="grid grid-cols-4 gap-2">
        <div className="surface-card p-3 text-center"><p className="caption">Total</p><p className="mt-1 text-sm font-semibold text-[var(--text-primary)]">{audit?.totalEntries ?? 0}</p></div>
        <div className="surface-card p-3 text-center"><p className="caption">Weak</p><p className="mt-1 text-sm font-semibold text-[var(--text-primary)]">{audit?.weakPasswords.length ?? 0}</p></div>
        <div className="surface-card p-3 text-center"><p className="caption">Reused</p><p className="mt-1 text-sm font-semibold text-[var(--text-primary)]">{audit?.reusedPasswords.length ?? 0}</p></div>
        <div className="surface-card p-3 text-center"><p className="caption">Strong</p><p className="mt-1 text-sm font-semibold text-[var(--text-primary)]">{audit?.strongEntries ?? 0}</p></div>
      </div>

      <div className="surface-card space-y-2 p-4">
        <p className="subheading">Issues</p>
        {issues.length > 0 ? (
          issues.map((issue) => (
            <p key={issue} className="text-sm text-[var(--text-primary)]">{issue}</p>
          ))
        ) : (
          <p className="text-sm text-[#0D9B6A]">All passwords look healthy.</p>
        )}
      </div>

      <div className="surface-card space-y-3 p-4">
        <div className="grid grid-cols-2 gap-2">
          <button type="button" className="rounded-xl bg-[var(--surface-alt)] py-2 text-sm text-[var(--text-primary)]">
            Generate Password
          </button>
          <button type="button" className="rounded-xl bg-[var(--surface-alt)] py-2 text-sm text-[var(--text-primary)]">
            Add Password
          </button>
        </div>

        <div className="grid grid-cols-2 gap-2">
          <button type="button" onClick={() => void exportVault()} className="rounded-xl bg-[#0D9B6A] py-2 text-sm font-semibold text-white">
            Export Vault
          </button>
          <button type="button" onClick={() => fileInputRef.current?.click()} className="rounded-xl border border-[var(--border)] py-2 text-sm text-[var(--text-secondary)]">
            Import Vault
          </button>
          <input
            ref={fileInputRef}
            type="file"
            accept=".json"
            className="hidden"
            onChange={(e) => void handleImport(e.target.files?.[0])}
          />
        </div>
        <p className="caption">Exports encrypted JSON only.</p>
        {message && <p className="text-xs text-[#0D9B6A]">{message}</p>}
        {error && <p className="text-xs text-[#EF4444]">{error}</p>}
      </div>
    </div>
  )
}
