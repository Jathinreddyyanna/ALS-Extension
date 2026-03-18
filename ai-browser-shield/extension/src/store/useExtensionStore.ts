import { create } from 'zustand';
import type { FileScanResult, UrlScanResult } from '@/types/index';

export type PopupTab = 'shield' | 'history' | 'report' | 'settings';

interface ExtensionSettings {
  protectionEnabled: boolean;
  autoBlockCritical: boolean;
  showHoverPreviews: boolean;
  allowFileScanning: boolean;
  showPopupNotifications: boolean;
}

interface ExtensionStore {
  currentTab: PopupTab;
  direction: number;
  currentUrl: string;
  currentDomain: string;
  currentTabId: number | null;
  sessionId: string;
  isScanning: boolean;
  scanStage: number;
  scanResult: UrlScanResult | null;
  scanError: string | null;
  reportStatus: 'idle' | 'submitting' | 'success' | 'error';
  dashboardPage: 'overview' | 'history' | 'reports' | 'downloads' | 'settings';
  settings: ExtensionSettings;
  downloadOverlay: { open: boolean; result: FileScanResult | null; fileName?: string; fileSize?: number };
  setCurrentTab: (tab: PopupTab) => void;
  setCurrentLocation: (url: string, domain: string, tabId: number | null) => void;
  setIsScanning: (value: boolean) => void;
  setScanStage: (value: number) => void;
  setScanResult: (result: UrlScanResult | null) => void;
  setScanError: (value: string | null) => void;
  setReportStatus: (value: ExtensionStore['reportStatus']) => void;
  setDashboardPage: (value: ExtensionStore['dashboardPage']) => void;
  updateSettings: (value: Partial<ExtensionSettings>) => void;
  setDownloadOverlay: (value: ExtensionStore['downloadOverlay']) => void;
}

export const defaultSettings: ExtensionSettings = {
  protectionEnabled: true,
  autoBlockCritical: true,
  showHoverPreviews: true,
  allowFileScanning: true,
  showPopupNotifications: true
};

export const useExtensionStore = create<ExtensionStore>((set, get) => ({
  currentTab: 'shield',
  direction: 1,
  currentUrl: '',
  currentDomain: '',
  currentTabId: null,
  sessionId: crypto.randomUUID(),
  isScanning: true,
  scanStage: 0,
  scanResult: null,
  scanError: null,
  reportStatus: 'idle',
  dashboardPage: 'overview',
  settings: defaultSettings,
  downloadOverlay: { open: false, result: null },
  setCurrentTab: (tab) => set({ direction: ['shield', 'history', 'report', 'settings'].indexOf(tab) > ['shield', 'history', 'report', 'settings'].indexOf(get().currentTab) ? 1 : -1, currentTab: tab }),
  setCurrentLocation: (url, domain, tabId) => set({ currentUrl: url, currentDomain: domain, currentTabId: tabId }),
  setIsScanning: (value) => set({ isScanning: value }),
  setScanStage: (value) => set({ scanStage: value }),
  setScanResult: (result) => set({ scanResult: result }),
  setScanError: (value) => set({ scanError: value }),
  setReportStatus: (value) => set({ reportStatus: value }),
  setDashboardPage: (value) => set({ dashboardPage: value }),
  updateSettings: (value) => set((state) => ({ settings: { ...state.settings, ...value } })),
  setDownloadOverlay: (value) => set({ downloadOverlay: value })
}));
