import createCache from '@emotion/cache';
import { CacheProvider } from '@emotion/react';
import { Alert, Button, CssBaseline, ThemeProvider, createTheme, useMediaQuery } from '@mui/material';
import { prefixer } from 'stylis';
import rtlPlugin from 'stylis-plugin-rtl';
import { createContext, lazy, Suspense, useCallback, useContext, useEffect, useMemo, useState, type ReactNode } from 'react';
import { BrowserRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import { type Account, get, post, setCsrfToken, setUnauthorizedHandler } from './lib/api';
import { PageBoundary } from './ui/errorBoundary';
import { Login } from './auth/login';
import { clearAccountCache, closeCache } from './mail/cache';
import { clearSensitiveSessionState } from './auth/sessionCleanup';
import { lock as lockPgp } from './mail/pgp';
import { type PackageInfo, startPackages } from './plugins/host';
import { PluginFrames } from './plugins/PluginFrames';
import { FeatureGate, PluginPage } from './plugins/Slot';
import { loadPrefs, type Prefs, primePrefs, updatePrefs, usePrefs } from './lib/prefs';
import { BUILT_IN_SKINS, buildTheme, sanitizeSkin, type Skin } from './ui/skins';

import { chosenLanguage, isRtl, setLanguage } from './i18n';
import { readLocal, writeLocal } from './lib/storage';
const LOGOUT_PENDING = 'unomail.logoutPending';
// The language is fixed for the page's lifetime, so the direction is too. Right to left, the
// styles are mirrored as they are inserted (margins, paddings, positions swap sides).
const RTL = isRtl();
const rtlCache = RTL ? createCache({ key: 'muirtl', stylisPlugins: [prefixer, rtlPlugin] }) : null;
const MailPage = lazy(() => import('./mail/MailPage'));
const AdminApp = lazy(() => import('./admin/AdminApp'));
const SettingsPage = lazy(() => import('./settings/SettingsPage'));
const ContactsPage = lazy(() => import('./contacts/ContactsPage'));
const CalendarPage = lazy(() => import('./calendar/CalendarPage'));
const Reminders = lazy(() => import('./calendar/Reminders').then((module) => ({ default: module.Reminders })));

/** What the server asks for when the account has two-step sign-in. */
export interface SecondFactorChallenge {
  token: string;
  methods: { totp: boolean; passkey: boolean; recovery: boolean };
  passkey: import('./auth/webauthn').RequestOptions | null;
}

/** An account this browser is signed in to. */
export interface SignedInAccount {
  account: Account;
  active: boolean;
  /** Unread messages in its inbox. */
  unread: number;
}

/** Tabs of the same browser share the session: a switch in one reloads the others. */
const accountChannel = typeof BroadcastChannel === 'undefined' ? null : new BroadcastChannel('unomail-account');

/** Tells the other tabs that the browser's current account changed. */
export function announceAccountChange() {
  accountChannel?.postMessage('changed');
}

interface AuthState {
  account: Account | null;
  /** Every account signed in on this browser, the current one first. */
  accounts: SignedInAccount[];
  refreshAccounts: () => Promise<void>;
  /** Makes another signed-in account the current one (the page reloads). */
  switchAccount: (id: number) => Promise<void>;
  /** Signs in with the password; returns the second step when one is needed. */
  login: (email: string, password: string, captcha?: string) => Promise<SecondFactorChallenge | null>;
  /** Completes a sign-in with what the second step returned. */
  completeLogin: (data: { account: Account; csrf_token: string }) => void;
  /** Signs out of the current account (or, with `all`, of every one). */
  logout: (all?: boolean) => Promise<void>;
}

const AuthContext = createContext<AuthState>({
  account: null, accounts: [], refreshAccounts: async () => {}, switchAccount: async () => {}, login: async () => null, completeLogin: () => {}, logout: async () => {},
});
export const useAuth = () => useContext(AuthContext);

type Mode = 'light' | 'dark' | 'system';
interface Appearance {
  mode: Mode;
  seed: string;
  /** The active skin and every skin that can be chosen. */
  skin: Skin;
  skins: Skin[];
  setMode: (mode: Mode) => void;
  setSeed: (seed: string) => void;
  setSkin: (id: string) => void;
  /** Re-reads the skins installed by the administrator. */
  reloadSkins: () => Promise<void>;
}
const AppearanceContext = createContext<Appearance>({
  mode: 'system', seed: '#6750a4', skin: BUILT_IN_SKINS[0], skins: BUILT_IN_SKINS, setMode: () => {}, setSeed: () => {}, setSkin: () => {}, reloadSkins: async () => {},
});
export const useAppearance = () => useContext(AppearanceContext);

/** Seed colours offered for the Material You dynamic colour scheme. */
export const SEEDS = ['#6750a4', '#0061a4', '#006e1c', '#b3261e', '#7d5260', '#006874', '#c2185b', '#b25e00', '#455a64'];

const stored = (key: string, fallback: string) => readLocal(key) ?? fallback;
const remember = (key: string, value: string) => void writeLocal(key, value);

/** The sign-in page; while signed in, only for adding another account (`?add=1`). */
function LoginRoute() {
  const { account } = useAuth();
  const location = useLocation();
  const adding = new URLSearchParams(location.search).get('add') === '1';
  return account && !adding ? <Navigate to="/mail" replace /> : <Login adding={Boolean(account) && adding} />;
}

function RequireAuth({ children, admin }: { children: ReactNode; admin?: boolean }) {
  const { account } = useAuth();
  const location = useLocation();
  // The query comes along: a mailto: link opened while signed out still writes its message.
  if (!account) return <Navigate to="/login" state={{ from: location.pathname + location.search }} replace />;
  if (admin && account.role === 'user') return <Navigate to="/mail" replace />;
  return <>{children}</>;
}

export function App() {
  const [account, setAccount] = useState<Account | null>(null);
  const [accounts, setAccounts] = useState<SignedInAccount[]>([]);
  const [loading, setLoading] = useState(true);
  const [logoutPending, setLogoutPending] = useState(() => readLocal(LOGOUT_PENDING) === 'true');
  const [mode, setModeState] = useState<Mode>(() => stored('unomail.mode', 'system') as Mode);
  const [seed, setSeedState] = useState(() => stored('unomail.seed', SEEDS[0]));
  // The skin is remembered on the device too, so the login page already uses it.
  const [skinId, setSkinId] = useState(() => stored('unomail.skin', BUILT_IN_SKINS[0].id));
  const [customSkins, setCustomSkins] = useState<Skin[]>([]);
  const prefersDark = useMediaQuery('(prefers-color-scheme: dark)');
  const prefs = usePrefs();

  const applySkins = useCallback((installed: unknown[]) => setCustomSkins(installed.map(sanitizeSkin).filter((skin): skin is Skin => skin !== null)), []);
  const reloadSkins = useCallback(async () => {
    try {
      // Skins pasted by the administrator, and the themes installed as packages.
      const [skins, packages] = await Promise.all([get<unknown[]>('/api/skins'), get<{ type: string; enabled: boolean; manifest: { theme?: unknown } }[]>('/api/packages').catch(() => [])]);
      applySkins([...skins, ...packages.filter((p) => p.type === 'theme' && p.enabled).map((p) => p.manifest.theme)]);
    } catch {
      setCustomSkins([]);
    }
  }, [applySkins]);

  const clearSession = useCallback(() => {
    setAccount(null);
    setAccounts([]);
    void clearSensitiveSessionState().catch(() => {});
  }, []);

  const retryLogout = useCallback(async () => {
    try {
      const current = await get<{ csrf_token: string }>('/api/auth/me');
      setCsrfToken(current.csrf_token);
      // A failed logout locks the entire browser until all remaining sessions are revoked.
      await post('/api/auth/logout', { all: true });
    } catch (error) {
      if (!(error instanceof Error && 'status' in error && error.status === 401)) return;
    } finally {
      clearSession();
    }
    writeLocal(LOGOUT_PENDING, null);
    setLogoutPending(false);
    accountChannel?.postMessage('signed-out');
  }, [clearSession]);

  useEffect(() => {
    setUnauthorizedHandler(clearSession);
    if (readLocal(LOGOUT_PENDING) === 'true') {
      clearSession();
      void retryLogout().finally(() => setLoading(false));
      return;
    }
    let cancelled = false;
    get<{ account: Account; csrf_token: string }>('/api/auth/me')
      .then((data) => {
        if (cancelled) return;
        setCsrfToken(data.csrf_token);
        setAccount(data.account);
      })
      .catch(clearSession)
      .finally(() => setLoading(false));
    return () => { cancelled = true; setUnauthorizedHandler(() => {}); };
  }, [clearSession, retryLogout]);

  useEffect(() => {
    if (!logoutPending) return;
    const retry = () => void retryLogout();
    window.addEventListener('online', retry);
    return () => window.removeEventListener('online', retry);
  }, [logoutPending, retryLogout]);

  const refreshAccounts = useCallback(async () => {
    try {
      setAccounts((await get<{ accounts: SignedInAccount[] }>('/api/auth/accounts')).accounts);
    } catch {
      setAccounts([]);
    }
  }, []);

  // Another tab switched or signed out: this one shows the browser's current account too.
  useEffect(() => {
    if (!accountChannel) return;
    const listener = () => window.location.reload();
    accountChannel.addEventListener('message', listener);
    return () => accountChannel.removeEventListener('message', listener);
  }, []);

  // Everything that belongs to the signed-in user: preferences, installed skins and plug-ins.
  useEffect(() => {
    if (!account) return;
    let cancelled = false;
    void refreshAccounts();
    // One request for what every page needs; the separate ones if it fails.
    get<{ preferences: Prefs; skins: unknown[]; themes?: unknown[]; packages?: PackageInfo[]; }>('/api/me/startup')
      .then((data) => {
        if (cancelled) return;
        primePrefs(data.preferences);
        applySkins([...data.skins, ...(data.themes ?? [])]);
        void startPackages(account.email, data.packages ?? []);
      })
      .catch(() => {
        if (cancelled) return;
        void loadPrefs();
        void reloadSkins();
        void startPackages(account.email);
      });
    return () => { cancelled = true; };
  }, [account, reloadSkins, applySkins, refreshAccounts]);

  // So does the interface language (switching it reloads the page once).
  useEffect(() => {
    if (prefs.language === undefined) return;
    const wanted = prefs.language || null;
    if (wanted !== chosenLanguage()) setLanguage(wanted);
  }, [prefs.language]);

  // The skin stored with the account wins over the one remembered on this device.
  useEffect(() => {
    if (prefs.skin && prefs.skin !== skinId) {
      setSkinId(prefs.skin);
      remember('unomail.skin', prefs.skin);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [prefs.skin]);

  const completeLogin = useCallback((data: { account: Account; csrf_token: string }) => {
    setCsrfToken(data.csrf_token);
    setAccount(data.account);
  }, []);
  const login = useCallback(
    async (email: string, password: string, captcha?: string) => {
      if (logoutPending) throw new Error('Confirm server sign-out before signing in again.');
      const data = await post<{ account?: Account; csrf_token?: string; second_factor?: SecondFactorChallenge }>('/api/auth/login', { email, password, captcha });
      if (data.second_factor) return data.second_factor;
      completeLogin({ account: data.account!, csrf_token: data.csrf_token! });
      return null;
    },
    [completeLogin, logoutPending],
  );
  const switchAccount = useCallback(async (id: number) => {
    await post('/api/auth/switch', { account_id: id });
    accountChannel?.postMessage('switched');
    // A fresh start: everything held in memory belongs to the account that was current.
    window.location.assign('/mail');
  }, []);
  const logout = useCallback(async (all = false) => {
    closeCache();
    lockPgp();
    writeLocal(LOGOUT_PENDING, 'true');
    let result: { next: { account: Account; csrf_token: string } | null };
    try {
      result = await post('/api/auth/logout', { all });
    } catch (error) {
      // 401: the server already ended the session (revoked by an administrator, expired), so
      // sign-out is confirmed. Anything else may mean the request never reached the server.
      if (error instanceof Error && 'status' in error && error.status === 401) {
        writeLocal(LOGOUT_PENDING, null);
        clearSession();
        accountChannel?.postMessage('signed-out');
        return;
      }
      setLogoutPending(true);
      clearSession();
      accountChannel?.postMessage('signed-out');
      return;
    }
    writeLocal(LOGOUT_PENDING, null);
    setLogoutPending(false);
    accountChannel?.postMessage('signed-out');
    if (result.next && account) {
      // Another account stays signed in: forget only this one's data, and carry on with that one.
      clearAccountCache(account.email);
      lockPgp();
      window.location.assign('/mail');
      return;
    }
    clearSession();
  }, [account, clearSession]);

  const skins = useMemo(() => [...BUILT_IN_SKINS, ...customSkins.filter((custom) => !BUILT_IN_SKINS.some((builtIn) => builtIn.id === custom.id))], [customSkins]);
  const skin = useMemo(() => skins.find((candidate) => candidate.id === skinId) ?? BUILT_IN_SKINS[0], [skins, skinId]);
  const appearance = useMemo<Appearance>(
    () => ({
      mode,
      seed,
      skin,
      skins,
      setMode: (next) => {
        setModeState(next);
        remember('unomail.mode', next);
      },
      setSeed: (next) => {
        setSeedState(next);
        remember('unomail.seed', next);
      },
      setSkin: (id) => {
        setSkinId(id);
        remember('unomail.skin', id);
        void updatePrefs({ skin: id }).catch(() => {});
      },
      reloadSkins,
    }),
    [mode, seed, skin, skins, reloadSkins],
  );
  const theme = useMemo(() => {
    const built = buildTheme(skin, seed, mode === 'dark' || (mode === 'system' && prefersDark));
    return RTL ? createTheme(built, { direction: 'rtl' }) : built;
  }, [skin, seed, mode, prefersDark]);
  const auth = useMemo(
    () => ({ account, accounts, refreshAccounts, switchAccount, login, completeLogin, logout }),
    [account, accounts, refreshAccounts, switchAccount, login, completeLogin, logout],
  );

  const page = (
    <AppearanceContext.Provider value={appearance}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthContext.Provider value={auth}>
          {logoutPending ? (
            <Alert severity="warning" sx={{ m: 3 }} action={<Button color="inherit" onClick={() => void retryLogout()}>Retry sign-out</Button>}>
              Mail is locked on this device, but server sign-out could not be confirmed. Reconnect and retry before leaving this shared device.
            </Alert>
          ) : loading ? null : (
            <BrowserRouter>
              {/* A boundary of its own: loading the reminders must not suspend (and remount) the pages. */}
              <Suspense fallback={null}>{account && <Reminders />}</Suspense>
              {account && <PluginFrames />}
              <PageBoundary>
              <Suspense fallback={null}>
                <Routes>
                  <Route path="/login" element={<LoginRoute />} />
                  <Route path="/mail/*" element={<RequireAuth><MailPage /></RequireAuth>} />
                  <Route path="/contacts" element={<RequireAuth><FeatureGate id="contacts" fallback={<Navigate to="/mail" replace />}><ContactsPage /></FeatureGate></RequireAuth>} />
                  <Route path="/calendar" element={<RequireAuth><FeatureGate id="calendar" fallback={<Navigate to="/mail" replace />}><CalendarPage /></FeatureGate></RequireAuth>} />
                  <Route path="/x/:plugin/:view" element={<RequireAuth><PluginPage /></RequireAuth>} />
                  <Route path="/settings" element={<RequireAuth><SettingsPage /></RequireAuth>} />
                  <Route path="/admin/*" element={<RequireAuth admin><AdminApp /></RequireAuth>} />
                  <Route path="*" element={<Navigate to="/mail" replace />} />
                </Routes>
              </Suspense>
              </PageBoundary>
            </BrowserRouter>
          )}
        </AuthContext.Provider>
      </ThemeProvider>
    </AppearanceContext.Provider>
  );
  return rtlCache ? <CacheProvider value={rtlCache}>{page}</CacheProvider> : page;
}
