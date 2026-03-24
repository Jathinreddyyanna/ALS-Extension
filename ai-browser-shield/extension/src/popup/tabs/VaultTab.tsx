import { useEffect, useMemo, useState } from 'react'
import { generatePassword, measurePasswordStrength } from '../../crypto/vault'
import { extractRootDomain } from '../../detection/trustEngine'
import { useVaultStore } from '../../store/useVaultStore'
import type { VaultEntry } from '../../types/vault'

function getAvatarColor(domain: string) {
  const char = domain.charCodeAt(0) || 1
  return `hsl(${char * 15}, 60%, 35%)`
}

type TrustState = 'match' | 'partial' | 'none'

const defaultForm = {
  title: '',
  domain: '',
  username: '',
  password: '',
  notes: '',
}

export const VaultTab = () => {
  const { entries, searchEntries, addEntry, updateEntry, deleteEntry } = useVaultStore()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<VaultEntry[]>([])
  const [expandedId, setExpandedId] = useState<string | null>(null)
  const [showPwIds, setShowPwIds] = useState<Set<string>>(new Set())
  const [copiedKey, setCopiedKey] = useState<string | null>(null)
  const [showAddForm, setShowAddForm] = useState(false)
  const [editId, setEditId] = useState<string | null>(null)
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const [form, setForm] = useState(defaultForm)
  const [formPwVisible, setFormPwVisible] = useState(false)
  const [inlineToast, setInlineToast] = useState<string | null>(null)
  const [trustMap, setTrustMap] = useState<Map<string, TrustState>>(new Map())

  useEffect(() => {
    let active = true
    const timeout = window.setTimeout(async () => {
      const next = await searchEntries(query)
      if (active) setResults(next)
    }, 200)

    return () => {
      active = false
      window.clearTimeout(timeout)
    }
  }, [query, searchEntries, entries])

  useEffect(() => {
    const loadTrust = async () => {
      chrome.tabs.query({ active: true, currentWindow: true }, async ([tab]) => {
        const tabDomain = extractRootDomain(tab?.url ?? '')
        const next = new Map<string, TrustState>()
        const freshResults = await searchEntries(query)
        setResults(freshResults)
        for (const entry of freshResults) {
          const entryDomain = extractRootDomain(entry.domain)
          if (entryDomain === tabDomain) next.set(entry.id, 'match')
          else if (tabDomain.includes(entryDomain) || entryDomain.includes(tabDomain)) next.set(entry.id, 'partial')
          else next.set(entry.id, 'none')
        }
        setTrustMap(next)
      })
    }
    void loadTrust()
  }, [entries, query, searchEntries])

  const sortedResults = useMemo(
    () =>
      [...results].sort((a, b) => {
        const aTime = a.lastUsed ?? a.updatedAt
        const bTime = b.lastUsed ?? b.updatedAt
        if (aTime !== bTime) return bTime - aTime
        return a.title.localeCompare(b.title)
      }),
    [results]
  )

  const formStrength = measurePasswordStrength(form.password || '')

  const resetForm = () => {
    setForm(defaultForm)
    setEditId(null)
    setShowAddForm(false)
    setFormPwVisible(false)
  }

  const handleCopy = async (id: string, field: 'username' | 'password', value: string) => {
    await navigator.clipboard.writeText(value)
    setCopiedKey(`${id}-${field}`)
    window.setTimeout(() => setCopiedKey(null), 2000)
  }

  const handleAutofill = async () => {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab?.id || !tab.url) return
      chrome.runtime.sendMessage({
        type: 'VAULT_AUTOFILL_REQUEST',
        payload: {
          url: tab.url,
          domain: extractRootDomain(tab.url),
          usernameSelector: null,
          passwordSelector: 'input[type="password"]',
          tabId: tab.id,
        },
      })
    })
    setInlineToast('Autofill request sent.')
    window.setTimeout(() => setInlineToast(null), 2000)
  }

  const handleSave = async () => {
    const payload = {
      title: form.title || form.domain,
      domain: form.domain,
      url: form.domain ? `https://${form.domain}` : '',
      username: form.username,
      password: form.password,
      notes: form.notes,
    }

    if (editId) {
      await updateEntry(editId, payload)
    } else {
      await addEntry(payload)
    }
    resetForm()
  }

  const openAdd = () => {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      const domain = extractRootDomain(tab?.url ?? '')
      setForm({ ...defaultForm, domain, title: domain })
      setShowAddForm(true)
      setEditId(null)
    })
  }

  return (
    <div className="space-y-4">
      <div className="surface-card space-y-3 p-4">
        <div className="flex gap-2">
          <input
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search passwords"
            className="flex-1 rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none"
          />
          <button type="button" onClick={openAdd} className="rounded-xl bg-[#0D9B6A] px-4 py-2 text-sm font-semibold text-white">
            + Add
          </button>
        </div>

        {showAddForm && (
          <div className="space-y-3 rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] p-3">
            <input value={form.title} onChange={(e) => setForm((current) => ({ ...current, title: e.target.value }))} placeholder="Title" className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
            <input value={form.domain} onChange={(e) => setForm((current) => ({ ...current, domain: e.target.value }))} placeholder="Domain" className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
            <input value={form.username} onChange={(e) => setForm((current) => ({ ...current, username: e.target.value }))} placeholder="Username" className="w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
            <div className="space-y-2">
              <div className="flex gap-2">
                <input
                  type={formPwVisible ? 'text' : 'password'}
                  value={form.password}
                  onChange={(e) => setForm((current) => ({ ...current, password: e.target.value }))}
                  placeholder="Password"
                  className="flex-1 rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none"
                />
                <button type="button" onClick={() => setFormPwVisible((value) => !value)} className="rounded-lg border border-[var(--border)] px-3 py-2 text-xs text-[var(--text-secondary)]">
                  {formPwVisible ? 'Hide' : 'Show'}
                </button>
                <button
                  type="button"
                  onClick={() => setForm((current) => ({ ...current, password: generatePassword({ length: 16, uppercase: true, lowercase: true, numbers: true, symbols: false, excludeAmbiguous: false }) }))}
                  className="rounded-lg bg-[#0D9B6A] px-3 py-2 text-xs font-semibold text-white"
                >
                  Generate
                </button>
              </div>
              <div className="flex gap-1">
                {[0, 1, 2, 3, 4].map((index) => (
                  <div key={index} className="h-1.5 flex-1 rounded-full" style={{ background: index <= formStrength.score ? '#0D9B6A' : 'var(--surface)' }} />
                ))}
              </div>
            </div>
            <textarea value={form.notes} onChange={(e) => setForm((current) => ({ ...current, notes: e.target.value }))} placeholder="Notes" className="min-h-20 w-full rounded-lg border border-[var(--border)] bg-[var(--surface)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none" />
            <div className="flex gap-2">
              <button type="button" onClick={() => void handleSave()} className="flex-1 rounded-xl bg-[#0D9B6A] py-2 text-sm font-semibold text-white">
                {editId ? 'Update' : 'Save'}
              </button>
              <button type="button" onClick={resetForm} className="flex-1 rounded-xl border border-[var(--border)] py-2 text-sm text-[var(--text-secondary)]">
                Cancel
              </button>
            </div>
          </div>
        )}
      </div>

      {sortedResults.length === 0 ? (
        <div className="surface-card flex flex-col items-center gap-3 p-8 text-center">
          <div className="text-4xl">🔐</div>
          <p className="subheading">No passwords saved yet</p>
          <button type="button" onClick={openAdd} className="rounded-xl bg-[#0D9B6A] px-4 py-2 text-sm font-semibold text-white">
            Add your first
          </button>
        </div>
      ) : (
        sortedResults.map((entry) => {
          const expanded = expandedId === entry.id
          const showPassword = showPwIds.has(entry.id)
          const trust = trustMap.get(entry.id) ?? 'none'
          const trustColor = trust === 'match' ? '#0D9B6A' : trust === 'partial' ? '#F59E0B' : '#6B7280'
          return (
            <div key={entry.id} className="surface-card p-4">
              <div className="flex items-start gap-3">
                <div
                  className="flex h-11 w-11 items-center justify-center rounded-full text-sm font-semibold text-white"
                  style={{ background: getAvatarColor(entry.domain || entry.title || 'v') }}
                >
                  {(entry.title || entry.domain || 'V')[0]?.toUpperCase()}
                </div>
                <button type="button" onClick={() => setExpandedId(expanded ? null : entry.id)} className="flex-1 text-left">
                  <div className="flex items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-[var(--text-primary)]">{entry.title}</p>
                    <span className="h-2.5 w-2.5 rounded-full" style={{ background: trustColor }} />
                  </div>
                  <p className="mt-1 text-xs text-[var(--text-secondary)]">{entry.username} · {entry.domain}</p>
                </button>
              </div>

              {expanded && (
                <div className="mt-4 space-y-3 border-t border-[var(--border)] pt-3">
                  <div className="space-y-1">
                    <p className="text-xs text-[var(--text-secondary)]">Password</p>
                    <div className="flex items-center gap-2">
                      <p className="flex-1 rounded-lg bg-[var(--surface-alt)] px-3 py-2 font-mono text-xs text-[var(--text-primary)]">
                        {showPassword ? entry.password : '••••••••••'}
                      </p>
                      <button
                        type="button"
                        onClick={() => {
                          const next = new Set(showPwIds)
                          if (next.has(entry.id)) next.delete(entry.id)
                          else next.add(entry.id)
                          setShowPwIds(next)
                        }}
                        className="rounded-lg border border-[var(--border)] px-3 py-2 text-xs text-[var(--text-secondary)]"
                      >
                        {showPassword ? 'Hide' : 'Show'}
                      </button>
                      <button
                        type="button"
                        onClick={() => void handleCopy(entry.id, 'password', entry.password)}
                        className="rounded-lg bg-[#0D9B6A] px-3 py-2 text-xs font-semibold text-white"
                      >
                        {copiedKey === `${entry.id}-password` ? 'Copied!' : 'Copy'}
                      </button>
                    </div>
                  </div>

                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={() => void handleCopy(entry.id, 'username', entry.username)}
                      className="rounded-xl border border-[var(--border)] py-2 text-xs text-[var(--text-secondary)]"
                    >
                      {copiedKey === `${entry.id}-username` ? 'Copied!' : 'Copy Username'}
                    </button>
                    <button
                      type="button"
                      onClick={() => void handleAutofill()}
                      className="rounded-xl bg-[#0D9B6A] py-2 text-xs font-semibold text-white"
                    >
                      Autofill
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        setEditId(entry.id)
                        setShowAddForm(true)
                        setForm({
                          title: entry.title,
                          domain: entry.domain,
                          username: entry.username,
                          password: entry.password,
                          notes: entry.notes ?? '',
                        })
                      }}
                      className="rounded-xl border border-[var(--border)] py-2 text-xs text-[var(--text-secondary)]"
                    >
                      Edit
                    </button>
                    <button
                      type="button"
                      onClick={() => {
                        if (deleteConfirmId === entry.id) {
                          void deleteEntry(entry.id)
                          setDeleteConfirmId(null)
                        } else {
                          setDeleteConfirmId(entry.id)
                        }
                      }}
                      className="rounded-xl border border-[#EF4444]/40 py-2 text-xs text-[#EF4444]"
                    >
                      {deleteConfirmId === entry.id ? 'Confirm delete' : 'Delete'}
                    </button>
                  </div>
                  {inlineToast && <p className="text-xs text-[#0D9B6A]">{inlineToast}</p>}
                </div>
              )}
            </div>
          )
        })
      )}
    </div>
  )
}
