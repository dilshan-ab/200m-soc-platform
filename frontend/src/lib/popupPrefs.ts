import { useSyncExternalStore } from 'react';

/** Which alert severities show a pop-up. Stored per browser; low covers low and info. */
export type PopupPrefs = { critical: boolean; high: boolean; medium: boolean; low: boolean };
export const DEFAULT_POPUP_PREFS: PopupPrefs = { critical: true, high: true, medium: true, low: true };
const KEY = '200m-alert-popups';
const listeners = new Set<() => void>();
let cache: PopupPrefs | null = null;

function read(): PopupPrefs {
  if (cache) return cache;
  try {
    const raw = localStorage.getItem(KEY);
    cache = raw ? { ...DEFAULT_POPUP_PREFS, ...(JSON.parse(raw) as Partial<PopupPrefs>) } : DEFAULT_POPUP_PREFS;
  } catch {
    cache = DEFAULT_POPUP_PREFS;
  }
  return cache;
}

export function setPopupPrefs(next: PopupPrefs): void {
  cache = next;
  try { localStorage.setItem(KEY, JSON.stringify(next)); } catch { /* private mode: keep for this session only */ }
  listeners.forEach((l) => l());
}

export function usePopupPrefs(): PopupPrefs {
  return useSyncExternalStore((l) => { listeners.add(l); return () => listeners.delete(l); }, read, read);
}

export function popupWanted(prefs: PopupPrefs, severity: string): boolean {
  if (severity === 'critical' || severity === 'high' || severity === 'medium') return prefs[severity];
  return prefs.low; // low and info
}

/** Test helper: forget the cached value so the next read comes from storage. */
export function resetPopupPrefsCache(): void { cache = null; }
