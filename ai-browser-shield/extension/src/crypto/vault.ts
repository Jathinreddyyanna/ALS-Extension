import type { VaultEntry, EncryptedVault, GeneratorOptions } from '../types/vault'

const PBKDF2_ITERATIONS = 310_000
const SALT_BYTES = 16
const IV_BYTES = 12
const VAULT_KEY = 'vaultshield_v1'

function toArrayBuffer(bytes: Uint8Array): ArrayBuffer {
  const copy = new Uint8Array(bytes.byteLength)
  copy.set(bytes)
  return copy.buffer
}

export function bufferToBase64(buf: ArrayBuffer | Uint8Array): string {
  const bytes = buf instanceof Uint8Array ? buf : new Uint8Array(buf)
  let out = ''
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i])
  return btoa(out)
}

export function base64ToBuffer(b64: string): Uint8Array {
  const input = atob(b64)
  const out = new Uint8Array(input.length)
  for (let i = 0; i < input.length; i++) out[i] = input.charCodeAt(i)
  return out
}

export const generateSalt = (): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(SALT_BYTES))

export const generateIV = (): Uint8Array =>
  crypto.getRandomValues(new Uint8Array(IV_BYTES))

export async function deriveKey(
  masterPassword: string,
  salt: Uint8Array
): Promise<CryptoKey> {
  const raw = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  )

  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt: toArrayBuffer(salt), iterations: PBKDF2_ITERATIONS, hash: 'SHA-256' },
    raw,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  )
}

export async function encryptEntries(
  entries: VaultEntry[],
  key: CryptoKey
): Promise<{ ciphertext: string; iv: string }> {
  const iv = generateIV()
  const plain = new TextEncoder().encode(JSON.stringify(entries))
  const cipher = await crypto.subtle.encrypt({ name: 'AES-GCM', iv: toArrayBuffer(iv) }, key, plain)
  return { ciphertext: bufferToBase64(cipher), iv: bufferToBase64(iv) }
}

export async function decryptEntries(
  ciphertext: string,
  iv: string,
  key: CryptoKey
): Promise<VaultEntry[]> {
  const plain = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: toArrayBuffer(base64ToBuffer(iv)) },
    key,
    toArrayBuffer(base64ToBuffer(ciphertext))
  )
  return JSON.parse(new TextDecoder().decode(plain)) as VaultEntry[]
}

export async function loadEncryptedVault(): Promise<EncryptedVault | null> {
  const result = await chrome.storage.local.get(VAULT_KEY)
  return result[VAULT_KEY] ?? null
}

export async function persistEncryptedVault(vault: EncryptedVault): Promise<void> {
  await chrome.storage.local.set({ [VAULT_KEY]: vault })
}

export async function wipeEncryptedVault(): Promise<void> {
  await chrome.storage.local.remove(VAULT_KEY)
}

export async function createAndPersistVault(
  masterPassword: string
): Promise<{ vault: EncryptedVault; key: CryptoKey }> {
  const salt = generateSalt()
  const key = await deriveKey(masterPassword, salt)
  const { ciphertext, iv } = await encryptEntries([], key)
  const vault: EncryptedVault = {
    salt: bufferToBase64(salt),
    iv,
    ciphertext,
    version: 1,
    createdAt: Date.now(),
    updatedAt: Date.now(),
  }
  await persistEncryptedVault(vault)
  return { vault, key }
}

export async function saveEntries(
  entries: VaultEntry[],
  key: CryptoKey,
  existing: EncryptedVault
): Promise<EncryptedVault> {
  const { ciphertext, iv } = await encryptEntries(entries, key)
  const updated: EncryptedVault = { ...existing, ciphertext, iv, updatedAt: Date.now() }
  await persistEncryptedVault(updated)
  return updated
}

export function measurePasswordStrength(password: string): {
  score: number
  label: 'weak' | 'fair' | 'strong' | 'very-strong'
  feedback: string[]
  entropy: number
} {
  const feedback: string[] = []
  let score = 0
  let charsetSize = 26

  if (/[A-Z]/.test(password)) {
    charsetSize += 26
    score++
  } else {
    feedback.push('Add uppercase letters')
  }
  if (/[0-9]/.test(password)) {
    charsetSize += 10
    score++
  } else {
    feedback.push('Add numbers')
  }
  if (/[^A-Za-z0-9]/.test(password)) {
    charsetSize += 32
    score++
  } else {
    feedback.push('Add symbols like !@#$')
  }
  if (password.length >= 12) {
    score++
  } else {
    feedback.push('Use at least 12 characters')
  }
  if (password.length >= 16) score++

  const entropy = password.length * Math.log2(charsetSize)
  const labels = ['weak', 'weak', 'fair', 'strong', 'strong', 'very-strong'] as const
  return { score, label: labels[Math.min(score, 5)], feedback, entropy }
}

export function estimateCrackTime(entropy: number): string {
  const seconds = Math.pow(2, entropy) / 1e10
  if (seconds < 1) return 'instantly'
  if (seconds < 60) return `${Math.round(seconds)}s`
  if (seconds < 3600) return `${Math.round(seconds / 60)} minutes`
  if (seconds < 86400) return `${Math.round(seconds / 3600)} hours`
  if (seconds < 31_536_000) return `${Math.round(seconds / 86400)} days`
  if (seconds < 3.15e9) return `${Math.round(seconds / 31_536_000)} years`
  return 'centuries'
}

export function generatePassword(opts: GeneratorOptions): string {
  let charset = ''
  if (opts.uppercase) charset += 'ABCDEFGHJKLMNPQRSTUVWXYZ'
  if (opts.lowercase) charset += 'abcdefghjkmnpqrstuvwxyz'
  if (opts.numbers) charset += opts.excludeAmbiguous ? '23456789' : '0123456789'
  if (opts.symbols) charset += '!@#$%^&*()_+-=[]{}|;:,.<>?'
  if (!charset) charset = 'abcdefghjkmnpqrstuvwxyz23456789'

  if (opts.excludeAmbiguous) {
    for (const char of 'Il1O0') charset = charset.replaceAll(char, '')
  }

  const arr = crypto.getRandomValues(new Uint32Array(opts.length))
  return Array.from(arr, (value) => charset[value % charset.length]).join('')
}

export function computeSecurityAudit(entries: VaultEntry[]) {
  const weak = entries.filter((entry) => entry.passwordStrength === 'weak' || entry.passwordStrength === 'fair')
  const passwordMap = new Map<string, VaultEntry[]>()
  for (const entry of entries) {
    passwordMap.set(entry.password, [...(passwordMap.get(entry.password) ?? []), entry])
  }
  const reused = [...passwordMap.values()].filter((group) => group.length > 1).flat()
  const cutoff = Date.now() - 90 * 86_400_000
  const old = entries.filter((entry) => entry.updatedAt < cutoff)
  const strong = entries.filter((entry) => entry.passwordStrength === 'very-strong').length

  let score = 100
  score -= weak.length * 10
  score -= reused.length * 15
  score -= old.length * 5
  score = Math.max(0, Math.min(100, score))

  return {
    overallScore: score,
    weakPasswords: weak,
    reusedPasswords: reused,
    oldPasswords: old,
    totalEntries: entries.length,
    strongEntries: strong,
  }
}
