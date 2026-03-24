import { useEffect, useState } from 'react'
import { estimateCrackTime, generatePassword, measurePasswordStrength } from '../../crypto/vault'
import { useVaultStore } from '../../store/useVaultStore'
import type { GeneratorOptions } from '../../types/vault'

const defaultOptions: GeneratorOptions = {
  length: 16,
  uppercase: true,
  lowercase: true,
  numbers: true,
  symbols: false,
  excludeAmbiguous: false,
}

function Toggle({
  label,
  checked,
  onChange,
}: {
  label: string
  checked: boolean
  onChange: (checked: boolean) => void
}) {
  return (
    <button
      type="button"
      onClick={() => onChange(!checked)}
      className="flex items-center justify-between rounded-xl border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-left"
    >
      <span className="text-sm text-[var(--text-primary)]">{label}</span>
      <span className={`relative h-5 w-10 rounded-full transition ${checked ? 'bg-[#0D9B6A]' : 'bg-[var(--border)]'}`}>
        <span className={`absolute top-0.5 h-4 w-4 rounded-full bg-white transition ${checked ? 'translate-x-5' : 'translate-x-0.5'}`} />
      </span>
    </button>
  )
}

export const GeneratorTab = () => {
  const { addEntry, unlocked } = useVaultStore()
  const [opts, setOpts] = useState<GeneratorOptions>(defaultOptions)
  const [generated, setGenerated] = useState('')
  const [copied, setCopied] = useState(false)
  const [showSave, setShowSave] = useState(false)
  const [saveForm, setSaveForm] = useState({ domain: '', username: '' })
  const [saved, setSaved] = useState(false)

  useEffect(() => {
    setGenerated(generatePassword(opts))
  }, [opts])

  useEffect(() => {
    setGenerated(generatePassword(defaultOptions))
  }, [])

  const { label, entropy, score } = measurePasswordStrength(generated)
  const crackTime = estimateCrackTime(entropy)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(generated)
    setCopied(true)
    window.setTimeout(() => setCopied(false), 2000)
  }

  const handleSave = async () => {
    await addEntry({
      title: saveForm.domain || 'Generated',
      domain: saveForm.domain,
      url: '',
      username: saveForm.username,
      password: generated,
      notes: '',
    })
    setSaved(true)
    setShowSave(false)
    setSaveForm({ domain: '', username: '' })
    setGenerated(generatePassword(opts))
    window.setTimeout(() => setSaved(false), 2000)
  }

  return (
    <div className="space-y-4">
      <div className="surface-card space-y-4 p-4">
        <div className="flex items-start justify-between gap-3 rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] p-3">
          <p className="max-w-[240px] break-all font-mono text-sm text-[var(--text-primary)]">{generated}</p>
          <div className="flex gap-2">
            <button type="button" onClick={() => setGenerated(generatePassword(opts))} className="rounded-lg bg-[var(--surface)] px-3 py-2 text-xs text-[var(--text-secondary)]">
              Refresh
            </button>
            <button type="button" onClick={() => void handleCopy()} className="rounded-lg bg-[#0D9B6A] px-3 py-2 text-xs font-semibold text-white">
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
        </div>

        <div className="space-y-2">
          <div className="flex gap-1">
            {[0, 1, 2, 3, 4].map((index) => (
              <div
                key={index}
                className="h-1.5 flex-1 rounded-full"
                style={{ background: index <= score ? '#0D9B6A' : 'var(--surface-alt)' }}
              />
            ))}
          </div>
          <p className="text-xs text-[var(--text-secondary)]">
            {label} · Cracked in: {crackTime}
          </p>
        </div>

        <div className="space-y-3">
          <label className="block text-sm text-[var(--text-primary)]">
            <span className="mb-2 block">Length: {opts.length}</span>
            <input
              type="range"
              min={8}
              max={64}
              value={opts.length}
              onChange={(e) => setOpts((current) => ({ ...current, length: Number(e.target.value) }))}
              className="w-full accent-[#0D9B6A]"
            />
          </label>

          <div className="grid grid-cols-2 gap-2">
            <Toggle label="Uppercase" checked={opts.uppercase} onChange={(uppercase) => setOpts((current) => ({ ...current, uppercase }))} />
            <Toggle label="Lowercase" checked={opts.lowercase} onChange={(lowercase) => setOpts((current) => ({ ...current, lowercase }))} />
            <Toggle label="Numbers" checked={opts.numbers} onChange={(numbers) => setOpts((current) => ({ ...current, numbers }))} />
            <Toggle label="Symbols" checked={opts.symbols} onChange={(symbols) => setOpts((current) => ({ ...current, symbols }))} />
          </div>

          <Toggle
            label="Exclude ambiguous (Il1O0)"
            checked={opts.excludeAmbiguous}
            onChange={(excludeAmbiguous) => setOpts((current) => ({ ...current, excludeAmbiguous }))}
          />
        </div>
      </div>

      <div className="surface-card space-y-3 p-4">
        <button
          type="button"
          onClick={() => setShowSave((value) => !value)}
          className="w-full rounded-xl bg-[#0D9B6A] py-2.5 text-sm font-semibold text-white"
        >
          {showSave ? 'Hide Save Form' : 'Save to Vault'}
        </button>

        {showSave && (
          <div className="space-y-3">
            {!unlocked && <p className="text-xs text-[#F59E0B]">Unlock the vault first to save generated passwords.</p>}
            <input
              value={saveForm.domain}
              onChange={(e) => setSaveForm((current) => ({ ...current, domain: e.target.value }))}
              placeholder="Domain"
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none"
            />
            <input
              value={saveForm.username}
              onChange={(e) => setSaveForm((current) => ({ ...current, username: e.target.value }))}
              placeholder="Username"
              className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none"
            />
            <div className="flex gap-2">
              <button
                type="button"
                onClick={() => void handleSave()}
                disabled={!unlocked || !saveForm.domain.trim()}
                className="flex-1 rounded-xl bg-[#0D9B6A] py-2 text-sm font-semibold text-white disabled:opacity-40"
              >
                Save
              </button>
              <button
                type="button"
                onClick={() => setShowSave(false)}
                className="flex-1 rounded-xl border border-[var(--border)] py-2 text-sm text-[var(--text-secondary)]"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {saved && <p className="text-xs text-[#0D9B6A]">Saved to vault.</p>}
      </div>
    </div>
  )
}
