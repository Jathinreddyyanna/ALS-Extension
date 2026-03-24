export interface VaultEntry {
  id: string
  domain: string
  url: string
  username: string
  password: string
  title: string
  favicon?: string
  createdAt: number
  updatedAt: number
  lastUsed?: number
  passwordStrength: 'weak' | 'fair' | 'strong' | 'very-strong'
  notes?: string
  tags?: string[]
}

export interface EncryptedVault {
  salt: string
  iv: string
  ciphertext: string
  version: number
  createdAt: number
  updatedAt: number
}

export interface TrustResult {
  score: number
  level: 'safe' | 'caution' | 'danger' | 'blocked'
  reasons: string[]
  matchedEntry?: VaultEntry
  isExactMatch: boolean
  similarityScore: number
  httpsPresent: boolean
  suspiciousPatterns: string[]
  autofillAllowed: boolean
}

export interface GeneratorOptions {
  length: number
  uppercase: boolean
  lowercase: boolean
  numbers: boolean
  symbols: boolean
  excludeAmbiguous: boolean
}

export interface SecurityAudit {
  overallScore: number
  weakPasswords: VaultEntry[]
  reusedPasswords: VaultEntry[]
  oldPasswords: VaultEntry[]
  totalEntries: number
  strongEntries: number
}

export type VaultCommand =
  | { type: 'VAULT_CREATE'; payload: { masterPassword: string } }
  | { type: 'VAULT_UNLOCK'; payload: { masterPassword: string } }
  | { type: 'VAULT_LOCK' }
  | { type: 'VAULT_GET_STATE' }
  | { type: 'VAULT_ADD_ENTRY'; payload: Omit<VaultEntry, 'id' | 'createdAt' | 'updatedAt' | 'passwordStrength'> }
  | { type: 'VAULT_UPDATE_ENTRY'; payload: { id: string; updates: Partial<VaultEntry> } }
  | { type: 'VAULT_DELETE_ENTRY'; payload: { id: string } }
  | { type: 'VAULT_SEARCH'; payload: { query: string } }
  | { type: 'VAULT_GET_AUDIT' }
  | { type: 'VAULT_EXPORT' }
  | { type: 'VAULT_IMPORT'; payload: { encryptedVault: EncryptedVault } }
  | {
      type: 'VAULT_AUTOFILL_REQUEST'
      payload: {
        url: string
        domain: string
        usernameSelector: string | null
        passwordSelector: string
        tabId: number
      }
    }
  | {
      type: 'VAULT_SAVE_ACCEPTED'
      payload: {
        domain: string
        url: string
        username: string
        password: string
      }
    }
  | { type: 'VAULT_MARK_USED'; payload: { id: string } }

export interface VaultStateResponse {
  hasVault: boolean
  unlocked: boolean
  entries: VaultEntry[]
  unlockedAt: number | null
}

export interface VaultCommandResponse {
  ok: boolean
  error?: string
  data?: unknown
}
