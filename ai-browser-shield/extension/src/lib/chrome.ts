import type { ThreatEvent } from '@/types/index';

const hasChrome = (): boolean => typeof chrome !== 'undefined' && typeof chrome.runtime !== 'undefined';

export const getCurrentTab = async (): Promise<chrome.tabs.Tab | null> => {
  if (!hasChrome() || !chrome.tabs?.query) {
    return { id: 0, url: window.location.href, title: document.title } as chrome.tabs.Tab;
  }
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] ?? null;
};

export const getStorageLocal = async <T>(key: string, fallback: T): Promise<T> => {
  if (!hasChrome() || !chrome.storage?.local) {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : fallback;
  }
  return new Promise((resolve) => {
    chrome.storage.local.get([key], (result) => {
      resolve((result[key] as T | undefined) ?? fallback);
    });
  });
};

export const setStorageLocal = async <T>(key: string, value: T): Promise<void> => {
  if (!hasChrome() || !chrome.storage?.local) {
    localStorage.setItem(key, JSON.stringify(value));
    return;
  }
  await chrome.storage.local.set({ [key]: value });
};

export const getStorageSync = async <T>(key: string, fallback: T): Promise<T> => {
  if (!hasChrome() || !chrome.storage?.sync) {
    const raw = localStorage.getItem(key);
    return raw ? JSON.parse(raw) as T : fallback;
  }
  return new Promise((resolve) => {
    chrome.storage.sync.get([key], (result) => {
      resolve((result[key] as T | undefined) ?? fallback);
    });
  });
};

export const setStorageSync = async <T>(key: string, value: T): Promise<void> => {
  if (!hasChrome() || !chrome.storage?.sync) {
    localStorage.setItem(key, JSON.stringify(value));
    return;
  }
  await chrome.storage.sync.set({ [key]: value });
};

export const appendThreatHistory = async (event: ThreatEvent): Promise<void> => {
  const current = await getStorageLocal<ThreatEvent[]>('shield-history', []);
  const next = [event, ...current].slice(0, 50);
  await setStorageLocal('shield-history', next);
};
