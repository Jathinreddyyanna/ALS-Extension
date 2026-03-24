import { useEffect, useState } from 'react'
import { measurePasswordStrength } from '../../crypto/vault'
import { useVaultStore } from '../../store/useVaultStore'

export const UnlockTab = () => {
  const { hasVault, isLoading, error, createVault, unlockVault, clearError } = useVaultStore()
  const [pw, setPw] = useState('')
  const [confirm, setConfirm] = useState('')
  const [show, setShow] = useState(false)
  const [showReset, setShowReset] = useState(false)
  const strength = !hasVault && pw ? measurePasswordStrength(pw) : null

  useEffect(() => {
    clearError()
  }, [clearError])

  const mismatch = !hasVault && confirm.length > 0 && pw !== confirm
  const tooWeak = !hasVault && (strength?.score ?? 0) < 2
  const disabled = isLoading || pw.length < 4 || mismatch || tooWeak

  const handleSubmit = async () => {
    if (hasVault) {
      await unlockVault(pw)
      return
    }
    if (pw !== confirm) return
    await createVault(pw)
  }

  const colors: Record<string, string> = {
    weak: '#EF4444',
    fair: '#F59E0B',
    strong: '#10B981',
    'very-strong': '#0D9B6A',
  }

  return (
    <div className="flex flex-col items-center gap-5 px-4 py-6">
      <div className="flex flex-col items-center gap-2 text-center">
        <div className="select-none text-5xl">🛡</div>
        <p className="text-base font-semibold text-[var(--text-primary)]">
          {hasVault ? 'Unlock VaultShield' : 'Create Your Vault'}
        </p>
        <p className="max-w-[220px] text-xs text-[var(--text-secondary)]">
          {hasVault
            ? 'Enter your master password to access saved credentials'
            : 'Your master password encrypts everything locally. It never leaves your device.'}
        </p>
      </div>

      <div className="w-full space-y-3">
        <div className="relative">
          <input
            type={show ? 'text' : 'password'}
            value={pw}
            onChange={(e) => setPw(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !disabled && void handleSubmit()}
            placeholder="Master password"
            className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2.5 pr-14 text-sm text-[var(--text-primary)] outline-none transition focus:border-[#0D9B6A]"
            autoFocus
          />
          <button
            type="button"
            onClick={() => setShow((value) => !value)}
            className="absolute right-3 top-1/2 -translate-y-1/2 text-[10px] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            {show ? 'Hide' : 'Show'}
          </button>
        </div>

        {strength && (
          <div className="space-y-1">
            <div className="flex gap-1">
              {[0, 1, 2, 3, 4].map((index) => (
                <div
                  key={index}
                  className="h-1.5 flex-1 rounded-full transition-all"
                  style={{ background: index <= strength.score ? colors[strength.label] : 'var(--surface-alt)' }}
                />
              ))}
            </div>
            <p className="text-[11px]" style={{ color: colors[strength.label] }}>
              {strength.label.replace('-', ' ')}
              {strength.feedback[0] ? ` - ${strength.feedback[0]}` : ''}
            </p>
          </div>
        )}

        {!hasVault && (
          <input
            type={show ? 'text' : 'password'}
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && !disabled && void handleSubmit()}
            placeholder="Confirm master password"
            className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2.5 text-sm text-[var(--text-primary)] outline-none transition focus:border-[#0D9B6A]"
          />
        )}

        {error && <p className="text-center text-[11px] text-[#EF4444]">{error}</p>}
        {mismatch && <p className="text-[11px] text-[#EF4444]">Passwords do not match</p>}

        <button
          type="button"
          onClick={() => void handleSubmit()}
          disabled={disabled}
          className="w-full rounded-xl bg-[#0D9B6A] py-2.5 text-sm font-semibold text-white transition hover:opacity-90 disabled:opacity-40"
        >
          {isLoading ? 'Working...' : hasVault ? 'Unlock Vault' : 'Create Vault'}
        </button>
      </div>

      {hasVault && !showReset && (
        <button
          type="button"
          onClick={() => setShowReset(true)}
          className="text-[11px] text-[var(--text-secondary)] underline transition hover:text-[#EF4444]"
        >
          Forgot password?
        </button>
      )}

      {showReset && (
        <div className="w-full space-y-2 rounded-xl border border-[#EF4444]/30 bg-[#EF4444]/10 p-3">
          <p className="text-center text-[11px] font-medium text-[#EF4444]">
            Warning: permanently deletes all saved passwords. Cannot be undone.
          </p>
          <div className="flex gap-2">
            <button
              type="button"
              onClick={() => setShowReset(false)}
              className="flex-1 rounded-lg border border-[var(--border)] py-1.5 text-[11px] text-[var(--text-secondary)]"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={async () => {
                await chrome.storage.local.remove('vaultshield_v1')
                window.location.reload()
              }}
              className="flex-1 rounded-lg bg-[#EF4444] py-1.5 text-[11px] font-semibold text-white"
            >
              Delete Everything
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
