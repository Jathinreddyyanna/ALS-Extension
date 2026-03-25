import type { ThreatEvent } from '@/types/index';
import { toHashedUrl } from './security';

/**
 * Returns true when the current runtime has access to the Chrome extension APIs.
 */
const hasChrome = (): boolean => typeof chrome !== 'undefined' && typeof chrome.runtime !== 'undefined';

/**
 * Returns the active tab in the current browser window.
 */
export const getCurrentTab = async (): Promise<chrome.tabs.Tab | null> => {
  if (!hasChrome() || !chrome.tabs?.query) {
    return { id: 0, url: window.location.href, title: document.title } as chrome.tabs.Tab;
  }
  const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
  return tabs[0] ?? null;
};

/**
 * Reads a value from local extension storage with a browser fallback.
 */
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

/**
 * Writes a value to local extension storage with a browser fallback.
 */
export const setStorageLocal = async <T>(key: string, value: T): Promise<void> => {
  if (!hasChrome() || !chrome.storage?.local) {
    localStorage.setItem(key, JSON.stringify(value));
    return;
  }
  await chrome.storage.local.set({ [key]: value });
};

/**
 * Reads a value from sync storage with a browser fallback.
 */
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

/**
 * Writes a value to sync storage with a browser fallback.
 */
export const setStorageSync = async <T>(key: string, value: T): Promise<void> => {
  if (!hasChrome() || !chrome.storage?.sync) {
    localStorage.setItem(key, JSON.stringify(value));
    return;
  }
  await chrome.storage.sync.set({ [key]: value });
};

/**
 * Appends a privacy-safe event snapshot to the popup history timeline.
 */
export const appendThreatHistory = async (event: ThreatEvent): Promise<void> => {
  const current = await getStorageLocal<ThreatEvent[]>('threatHistory', []);
  const next = [{
    ...event,
    url: await toHashedUrl(event.url),
  }, ...current].slice(0, 50);
  await setStorageLocal('threatHistory', next);
};
