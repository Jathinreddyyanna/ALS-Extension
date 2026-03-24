import type {
  VaultEntry,
  EncryptedVault,
  VaultCommand,
  VaultCommandResponse,
  VaultStateResponse,
} from '../types/vault'
import {
  loadEncryptedVault,
  createAndPersistVault,
  saveEntries,
  decryptEntries,
  deriveKey,
  measurePasswordStrength,
  computeSecurityAudit,
  base64ToBuffer,
  wipeEncryptedVault,
  persistEncryptedVault,
} from '../crypto/vault'
import { evaluateTrust } from '../detection/trustEngine'

let encryptedVaultState: EncryptedVault | null = null
let sessionKeyState: CryptoKey | null = null
let entriesState: VaultEntry[] = []
let unlockedAtState: number | null = null

const SESSION_TIMEOUT_MS = 15 * 60 * 1000

function lockVaultState() {
  sessionKeyState = null
  entriesState = []
  unlockedAtState = null
}

export function isUnlocked(): boolean {
  if (!sessionKeyState || !unlockedAtState) return false
  if (Date.now() - unlockedAtState > SESSION_TIMEOUT_MS) {
    lockVaultState()
    return false
  }
  return true
}

export function getVaultState(): VaultStateResponse {
  return {
    hasVault: encryptedVaultState !== null,
    unlocked: isUnlocked(),
    entries: isUnlocked() ? entriesState : [],
    unlockedAt: unlockedAtState,
  }
}

export async function initVaultWorker(): Promise<void> {
  encryptedVaultState = await loadEncryptedVault()
}

async function handleCreate(masterPassword: string): Promise<VaultCommandResponse> {
  try {
    const { vault, key } = await createAndPersistVault(masterPassword)
    encryptedVaultState = vault
    sessionKeyState = key
    entriesState = []
    unlockedAtState = Date.now()
    return { ok: true }
  } catch {
    return { ok: false, error: 'Failed to create vault' }
  }
}

async function handleUnlock(masterPassword: string): Promise<VaultCommandResponse> {
  if (!encryptedVaultState) return { ok: false, error: 'No vault found' }
  try {
    const salt = base64ToBuffer(encryptedVaultState.salt)
    const key = await deriveKey(masterPassword, salt)
    const entries = await decryptEntries(encryptedVaultState.ciphertext, encryptedVaultState.iv, key)
    sessionKeyState = key
    entriesState = entries
    unlockedAtState = Date.now()
    return { ok: true }
  } catch {
    return { ok: false, error: 'Wrong master password' }
  }
}

async function handleAddEntry(
  data: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt' | 'passwordStrength'>
): Promise<VaultCommandResponse> {
  if (!isUnlocked() || !sessionKeyState || !encryptedVaultState) {
    return { ok: false, error: 'Vault is locked' }
  }

  const { label } = measurePasswordStrength(data.password)
  const entry: VaultEntry = {
    ...data,
    id: crypto.randomUUID(),
    createdAt: Date.now(),
    updatedAt: Date.now(),
    passwordStrength: label,
  }
  entriesState = [...entriesState, entry]
  encryptedVaultState = await saveEntries(entriesState, sessionKeyState, encryptedVaultState)
  return { ok: true, data: entry }
}

async function handleUpdateEntry(id: string, updates: Partial<VaultEntry>): Promise<VaultCommandResponse> {
  if (!isUnlocked() || !sessionKeyState || !encryptedVaultState) {
    return { ok: false, error: 'Vault is locked' }
  }

  entriesState = entriesState.map((entry) =>
    entry.id !== id
      ? entry
      : {
          ...entry,
          ...updates,
          updatedAt: Date.now(),
          passwordStrength: updates.password
            ? measurePasswordStrength(updates.password).label
            : entry.passwordStrength,
        }
  )
  encryptedVaultState = await saveEntries(entriesState, sessionKeyState, encryptedVaultState)
  return { ok: true }
}

async function handleDeleteEntry(id: string): Promise<VaultCommandResponse> {
  if (!isUnlocked() || !sessionKeyState || !encryptedVaultState) {
    return { ok: false, error: 'Vault is locked' }
  }

  entriesState = entriesState.filter((entry) => entry.id !== id)
  encryptedVaultState = await saveEntries(entriesState, sessionKeyState, encryptedVaultState)
  return { ok: true }
}

async function handleMarkUsed(id: string): Promise<void> {
  if (!isUnlocked() || !sessionKeyState || !encryptedVaultState) return

  entriesState = entriesState.map((entry) =>
    entry.id === id ? { ...entry, lastUsed: Date.now() } : entry
  )
  encryptedVaultState = await saveEntries(entriesState, sessionKeyState, encryptedVaultState)
}

export function handleAutofillRequest(payload: {
  url: string
  domain: string
  usernameSelector: string | null
  passwordSelector: string
  tabId: number
}) {
  const trust = evaluateTrust(payload.url, isUnlocked() ? entriesState : [])

  if (!trust.autofillAllowed || !trust.matchedEntry) {
    return { allowed: false, trustResult: trust }
  }

  void handleMarkUsed(trust.matchedEntry.id)

  return {
    allowed: true,
    username: trust.matchedEntry.username,
    password: trust.matchedEntry.password,
    trustResult: trust,
  }
}

export async function handleSaveAccepted(payload: {
  domain: string
  url: string
  username: string
  password: string
}): Promise<void> {
  if (!isUnlocked()) return

  await handleAddEntry({
    domain: payload.domain,
    url: payload.url,
    username: payload.username,
    password: payload.password,
    title: payload.domain,
  })
}

export async function dispatchVaultCommand(
  message: VaultCommand
): Promise<VaultCommandResponse | VaultStateResponse | unknown> {
  if (isUnlocked() && unlockedAtState) unlockedAtState = Date.now()

  switch (message.type) {
    case 'VAULT_CREATE':
      return handleCreate(message.payload.masterPassword)
    case 'VAULT_UNLOCK':
      return handleUnlock(message.payload.masterPassword)
    case 'VAULT_LOCK':
      lockVaultState()
      return { ok: true }
    case 'VAULT_GET_STATE':
      return getVaultState()
    case 'VAULT_ADD_ENTRY':
      return handleAddEntry(message.payload)
    case 'VAULT_UPDATE_ENTRY':
      return handleUpdateEntry(message.payload.id, message.payload.updates)
    case 'VAULT_DELETE_ENTRY':
      return handleDeleteEntry(message.payload.id)
    case 'VAULT_MARK_USED':
      await handleMarkUsed(message.payload.id)
      return { ok: true }
    case 'VAULT_GET_AUDIT':
      return isUnlocked()
        ? { ok: true, data: computeSecurityAudit(entriesState) }
        : { ok: false, error: 'Vault is locked' }
    case 'VAULT_SEARCH': {
      if (!isUnlocked()) return { ok: true, data: [] }
      const query = message.payload.query.toLowerCase()
      const results = query
        ? entriesState.filter((entry) =>
            entry.title.toLowerCase().includes(query) ||
            entry.domain.toLowerCase().includes(query) ||
            entry.username.toLowerCase().includes(query)
          )
        : entriesState
      return { ok: true, data: results }
    }
    case 'VAULT_EXPORT':
      return encryptedVaultState
        ? { ok: true, data: encryptedVaultState }
        : { ok: false, error: 'No vault to export' }
    case 'VAULT_IMPORT':
      await wipeEncryptedVault()
      lockVaultState()
      encryptedVaultState = null
      await persistEncryptedVault(message.payload.encryptedVault)
      encryptedVaultState = message.payload.encryptedVault
      return { ok: true }
    default:
      return { ok: false, error: 'Unknown vault command' }
  }
}

export function setupVaultSessionAlarm(): void {
  const globalWithTimer = globalThis as typeof globalThis & { setInterval?: typeof setInterval }
  if (typeof globalWithTimer.setInterval === 'function') {
    globalWithTimer.setInterval(() => {
      isUnlocked()
    }, 60_000)
  }
}
