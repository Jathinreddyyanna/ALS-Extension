import { useEffect, useState } from 'react';
import { getStorageSync, setStorageSync } from '@/lib/chrome';
import { useExtensionStore } from '@/store/useExtensionStore';
import { useVaultStore } from '../../store/useVaultStore';

const entries = [
  { key: 'protectionEnabled', title: 'Enable protection', description: 'Keeps scans running quietly in the background.' },
  { key: 'autoBlockCritical', title: 'Block critical sites automatically', description: 'Shows the strongest warning first when a site looks clearly unsafe.' },
  { key: 'showHoverPreviews', title: 'Show hover previews', description: 'Preview link risk before you click.' },
  { key: 'allowFileScanning', title: 'Allow file scanning', description: 'Checks files before they finish downloading.' },
  { key: 'showPopupNotifications', title: 'Show popup notifications', description: 'Lets you know when something needs attention.' }
] as const;

export const SettingsTab = () => {
  const { settings, updateSettings } = useExtensionStore();
  const { unlocked, lockVault } = useVaultStore();
  const [geminiKey, setGeminiKey] = useState('');
  const [saveMessage, setSaveMessage] = useState<string | null>(null);

  useEffect(() => {
    void getStorageSync('shield-settings', settings).then((stored) => updateSettings(stored));
  }, [updateSettings]);

  useEffect(() => {
    void getStorageSync('geminiApiKey', '').then((stored) => setGeminiKey(stored));
  }, []);

  const toggle = async (key: typeof entries[number]['key']) => {
    const next = { ...settings, [key]: !settings[key] };
    updateSettings(next);
    await setStorageSync('shield-settings', next);
  };

  const saveGeminiKey = async () => {
    await setStorageSync('geminiApiKey', geminiKey.trim());
    setSaveMessage('Gemini API key saved.');
    window.setTimeout(() => setSaveMessage(null), 2200);
  };

  return (
    <div className="space-y-3">
      {entries.map((entry) => (
        <div key={entry.key} className="surface-card flex items-start justify-between gap-4 p-4">
          <div className="pr-4">
            <p className="subheading">{entry.title}</p>
            <p className="caption mt-1">{entry.description}</p>
          </div>
          <button
            type="button"
            aria-pressed={settings[entry.key]}
            onClick={() => void toggle(entry.key)}
            className={`relative mt-1 h-7 w-12 rounded-full transition-colors ${settings[entry.key] ? 'bg-safe-600 dark:bg-safe-dark' : 'bg-[var(--border)]'}`}
          >
            <span className={`absolute top-1 h-5 w-5 rounded-full bg-white transition-transform ${settings[entry.key] ? 'translate-x-6' : 'translate-x-1'}`} />
          </button>
        </div>
      ))}
      <div className="surface-card space-y-3 p-4">
        <div>
          <p className="subheading">Your Gemini API key</p>
          <p className="caption mt-1">Optional. Bring your own key if shared quota runs out.</p>
        </div>
        <input
          type="password"
          value={geminiKey}
          onChange={(event) => setGeminiKey(event.target.value)}
          placeholder="AIzaSy..."
          className="w-full rounded-xl border border-[var(--border)] bg-[var(--surface-alt)] px-3 py-2 text-sm text-[var(--text-primary)] outline-none transition focus:border-safe-600"
        />
        <div className="flex items-center justify-between gap-3">
          <a
            href="https://aistudio.google.com/app/apikey"
            target="_blank"
            rel="noreferrer"
            className="caption text-safe-600 underline-offset-2 hover:underline"
          >
            Get a free key from Google AI Studio
          </a>
          <button
            type="button"
            onClick={() => void saveGeminiKey()}
            className="rounded-full bg-safe-600 px-4 py-2 text-xs font-semibold text-white transition hover:opacity-90"
          >
            Save
          </button>
        </div>
        {saveMessage && <p className="caption text-safe-600">{saveMessage}</p>}
      </div>
      <div className="surface-card space-y-3 p-4">
        <div>
          <p className="subheading">VaultShield Vault</p>
          <p className="caption mt-1">Manage your encrypted password vault.</p>
        </div>
        {unlocked ? (
          <button
            type="button"
            onClick={() => void lockVault()}
            className="w-full rounded-xl border border-[var(--border)] py-2 text-sm text-[var(--text-secondary)] transition hover:border-[#EF4444] hover:text-[#EF4444]"
          >
            Lock Vault Now
          </button>
        ) : (
          <p className="caption text-[var(--text-secondary)]">Vault is locked.</p>
        )}
        <p className="caption text-[var(--text-secondary)]">
          Vault auto-locks after 15 minutes of inactivity.
          All passwords are encrypted with AES-256-GCM locally.
          Your master password never leaves your device.
        </p>
      </div>
    </div>
  );
};
