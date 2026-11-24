import { useSyncExternalStore } from 'react';

/** Pop-ups are only for critical and high alerts; each can be switched off. Stored per browser. */
export type PopupPrefs = { critical: boolean; high: boolean };
export const DEFAULT_POPUP_PREFS: PopupPrefs = { critical: true, high: true };
const KEY = '200m-alert-popups';
const listeners = new Set<() => void>();
let cache: PopupPrefs | null = null;

function read(): PopupPrefs {
  if (cache) return cache;
  try {
    const raw = localStorage.getItem(KEY);
    const saved = raw ? (JSON.parse(raw) as Partial<PopupPrefs>) : {};
    cache = { critical: saved.critical ?? true, high: saved.high ?? true }; // older saved settings may also hold medium/low: ignored
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
  if (severity === 'critical' || severity === 'high') return prefs[severity];
  return false; // medium, low and info never pop up
}

/** Test helper: forget the cached value so the next read comes from storage. */
export function resetPopupPrefsCache(): void { cache = null; }
