import { useSyncExternalStore } from 'react';

export type ThemeMode = 'light' | 'dark' | 'system';
export type ResolvedTheme = 'light' | 'dark';

const THEME_STORAGE_KEY = 'culkibo_theme';

const listeners = new Set<() => void>();

function readInitialTheme(): ThemeMode {
  if (typeof window === 'undefined') return 'light';
  try {
    const params = new URLSearchParams(window.location.search);
    const qTheme = params.get('theme')?.toLowerCase();
    if (qTheme === 'light' || qTheme === 'dark' || qTheme === 'system') {
      window.localStorage.setItem(THEME_STORAGE_KEY, qTheme);
      return qTheme;
    }
  } catch {
    // ignore
  }
  try {
    const saved = window.localStorage.getItem(THEME_STORAGE_KEY);
    if (saved === 'light' || saved === 'dark' || saved === 'system') return saved;
  } catch {
    // ignore
  }
  return 'light';
}

function getSystemTheme(): ResolvedTheme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'light';
  return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

let currentMode: ThemeMode = readInitialTheme();
let resolvedTheme: ResolvedTheme = currentMode === 'system' ? getSystemTheme() : currentMode;

function applyThemeToDom(resolved: ResolvedTheme): void {
  if (typeof document === 'undefined') return;
  const root = document.documentElement;
  if (resolved === 'dark') {
    root.classList.add('dark');
    root.classList.remove('light');
    root.style.colorScheme = 'dark';
  } else {
    root.classList.remove('dark');
    root.classList.add('light');
    root.style.colorScheme = 'light';
  }
}

applyThemeToDom(resolvedTheme);

if (typeof window !== 'undefined' && window.matchMedia) {
  const mql = window.matchMedia('(prefers-color-scheme: dark)');
  const onChange = () => {
    if (currentMode === 'system') {
      resolvedTheme = getSystemTheme();
      applyThemeToDom(resolvedTheme);
      for (const fn of listeners) fn();
    }
  };
  if (typeof mql.addEventListener === 'function') {
    mql.addEventListener('change', onChange);
  }
}

export function getTheme(): ThemeMode {
  return currentMode;
}

export function getResolvedTheme(): ResolvedTheme {
  return resolvedTheme;
}

export function setTheme(mode: ThemeMode): void {
  if (mode !== 'light' && mode !== 'dark' && mode !== 'system') return;
  currentMode = mode;
  resolvedTheme = mode === 'system' ? getSystemTheme() : mode;
  applyThemeToDom(resolvedTheme);
  try {
    window.localStorage.setItem(THEME_STORAGE_KEY, mode);
  } catch {
    // ignore
  }
  for (const fn of listeners) fn();
}

export function toggleTheme(): ResolvedTheme {
  const next: ThemeMode = resolvedTheme === 'dark' ? 'light' : 'dark';
  setTheme(next);
  return resolvedTheme;
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => listeners.delete(cb);
}

export function useTheme() {
  const mode = useSyncExternalStore(subscribe, getTheme, () => 'light' as ThemeMode);
  const resolved = useSyncExternalStore(subscribe, getResolvedTheme, () => 'light' as ResolvedTheme);
  return {
    theme: mode,
    resolvedTheme: resolved,
    isDark: resolved === 'dark',
    setTheme,
    toggleTheme,
  };
}
