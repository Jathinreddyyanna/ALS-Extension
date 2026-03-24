import { create } from 'zustand'
import type { VaultEntry, SecurityAudit, VaultStateResponse } from '../types/vault'

function sendToBackground<T>(message: object): Promise<T> {
  return new Promise((resolve, reject) => {
    chrome.runtime.sendMessage(message, (response) => {
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message))
      } else {
        resolve(response as T)
      }
    })
  })
}

interface VaultStore {
  hasVault: boolean
  unlocked: boolean
  entries: VaultEntry[]
  isLoading: boolean
  error: string | null
  audit: SecurityAudit | null
  syncState: () => Promise<void>
  createVault: (masterPassword: string) => Promise<boolean>
  unlockVault: (masterPassword: string) => Promise<boolean>
  lockVault: () => Promise<void>
  addEntry: (data: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt' | 'passwordStrength'>) => Promise<void>
  updateEntry: (id: string, updates: Partial<VaultEntry>) => Promise<void>
  deleteEntry: (id: string) => Promise<void>
  searchEntries: (query: string) => Promise<VaultEntry[]>
  fetchAudit: () => Promise<void>
  exportVault: () => Promise<void>
  importVault: (file: File) => Promise<void>
  clearError: () => void
}

export const useVaultStore = create<VaultStore>((set, get) => ({
  hasVault: false,
  unlocked: false,
  entries: [],
  isLoading: false,
  error: null,
  audit: null,

  syncState: async () => {
    try {
      const state = await sendToBackground<VaultStateResponse>({ type: 'VAULT_GET_STATE' })
      set({
        hasVault: state.hasVault,
        unlocked: state.unlocked,
        entries: state.entries,
      })
    } catch {
      set({ error: 'Could not reach background worker' })
    }
  },

  createVault: async (masterPassword) => {
    set({ isLoading: true, error: null })
    try {
      const res = await sendToBackground<{ ok: boolean; error?: string }>(
        { type: 'VAULT_CREATE', payload: { masterPassword } }
      )
      if (!res.ok) {
        set({ isLoading: false, error: res.error ?? 'Failed' })
        return false
      }
      await get().syncState()
      set({ isLoading: false })
      return true
    } catch {
      set({ isLoading: false, error: 'Failed to create vault' })
      return false
    }
  },

  unlockVault: async (masterPassword) => {
    set({ isLoading: true, error: null })
    try {
      const res = await sendToBackground<{ ok: boolean; error?: string }>(
        { type: 'VAULT_UNLOCK', payload: { masterPassword } }
      )
      if (!res.ok) {
        set({ isLoading: false, error: res.error ?? 'Wrong password' })
        return false
      }
      await get().syncState()
      set({ isLoading: false })
      return true
    } catch {
      set({ isLoading: false, error: 'Failed to unlock' })
      return false
    }
  },

  lockVault: async () => {
    await sendToBackground({ type: 'VAULT_LOCK' }).catch(() => {})
    set({ unlocked: false, entries: [], audit: null })
  },

  addEntry: async (data) => {
    set({ isLoading: true, error: null })
    try {
      await sendToBackground({ type: 'VAULT_ADD_ENTRY', payload: data })
      await get().syncState()
    } finally {
      set({ isLoading: false })
    }
  },

  updateEntry: async (id, updates) => {
    await sendToBackground({ type: 'VAULT_UPDATE_ENTRY', payload: { id, updates } })
    await get().syncState()
  },

  deleteEntry: async (id) => {
    await sendToBackground({ type: 'VAULT_DELETE_ENTRY', payload: { id } })
    await get().syncState()
  },

  searchEntries: async (query) => {
    const res = await sendToBackground<{ ok: boolean; data: VaultEntry[] }>(
      { type: 'VAULT_SEARCH', payload: { query } }
    )
    return res.data ?? []
  },

  fetchAudit: async () => {
    const res = await sendToBackground<{ ok: boolean; data: SecurityAudit }>(
      { type: 'VAULT_GET_AUDIT' }
    )
    if (res.ok) set({ audit: res.data })
  },

  exportVault: async () => {
    const res = await sendToBackground<{ ok: boolean; data: object }>(
      { type: 'VAULT_EXPORT' }
    )
    if (!res.ok || !res.data) return
    const blob = new Blob([JSON.stringify(res.data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `vaultshield-backup-${new Date().toISOString().slice(0, 10)}.json`
    a.click()
    URL.revokeObjectURL(url)
  },

  importVault: async (file) => {
    try {
      const text = await file.text()
      const encryptedVault = JSON.parse(text)
      await sendToBackground({ type: 'VAULT_IMPORT', payload: { encryptedVault } })
      await get().syncState()
    } catch {
      set({ error: 'Import failed - invalid file' })
    }
  },

  clearError: () => set({ error: null }),
}))
