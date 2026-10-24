// The captcha of the sign-in page: hCaptcha, Turnstile or reCAPTCHA in the provider's own
// widget, or ALTCHA, a proof of work this page solves by itself.

import CheckCircle from '@mui/icons-material/CheckCircle';
import { Alert, Box, CircularProgress, Stack, Typography, useTheme } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { get } from '../lib/api';
import { currentLanguage, t } from '../i18n';

interface AltchaChallenge {
  algorithm: string;
  challenge: string;
  maxnumber: number;
  salt: string;
  signature: string;
}

type Config = { provider: null } | { provider: 'hcaptcha' | 'turnstile' | 'recaptcha'; site_key: string } | { provider: 'altcha'; challenge: AltchaChallenge };

/** The common part of the three providers' scripts: `render`, `reset` and `remove`. */
interface WidgetApi {
  render: (element: HTMLElement, options: Record<string, unknown>) => string | number;
  reset: (id?: string | number) => void;
  remove?: (id?: string | number) => void;
}

const SCRIPTS = {
  hcaptcha: { url: 'https://js.hcaptcha.com/1/api.js', global: 'hcaptcha' },
  turnstile: { url: 'https://challenges.cloudflare.com/turnstile/v0/api.js', global: 'turnstile' },
  recaptcha: { url: 'https://www.google.com/recaptcha/api.js', global: 'grecaptcha' },
} as const;

const loading: Partial<Record<keyof typeof SCRIPTS, Promise<WidgetApi>>> = {};

function loadScript(provider: keyof typeof SCRIPTS): Promise<WidgetApi> {
  const { url, global } = SCRIPTS[provider];
  loading[provider] ??= new Promise((resolve, reject) => {
    const callback = `unomailCaptcha_${provider}`;
    (window as unknown as Record<string, () => void>)[callback] = () => resolve((window as unknown as Record<string, WidgetApi>)[global]);
    const script = document.createElement('script');
    script.src = `${url}?render=explicit&onload=${callback}&hl=${encodeURIComponent(currentLanguage())}`;
    script.async = true;
    script.onerror = () => {
      delete loading[provider];
      reject(new Error('captcha script'));
    };
    document.head.appendChild(script);
  });
  return loading[provider];
}

async function sha256Hex(text: string): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text)));
  return Array.from(digest, (b) => b.toString(16).padStart(2, '0')).join('');
}

/** Finds the number behind an ALTCHA challenge and returns the answer the server expects. */
async function solveAltcha(challenge: AltchaChallenge, cancelled: () => boolean): Promise<string | null> {
  for (let number = 0; number <= challenge.maxnumber; number++) {
    if (number % 1000 === 0 && cancelled()) return null;
    if ((await sha256Hex(challenge.salt + number)) === challenge.challenge) {
      const { algorithm, salt, signature } = challenge;
      return btoa(JSON.stringify({ algorithm, challenge: challenge.challenge, number, salt, signature }));
    }
  }
  return null;
}

/**
 * Shows the configured captcha and reports its answer: `null` while unanswered (also after
 * an answer expires). Nothing is reported when no captcha is set up. Changing `resetKey`
 * asks for a new answer: each one signs in only once.
 */
export function Captcha({ onAnswer, resetKey }: { onAnswer: (answer: string | null) => void; resetKey: number }) {
  const [config, setConfig] = useState<Config | null>(null);
  const [failed, setFailed] = useState(false);
  const report = useRef(onAnswer);
  report.current = onAnswer;

  // ALTCHA needs a fresh challenge every time, so the configuration is fetched again.
  useEffect(() => {
    let cancelled = false;
    get<Config>('/api/auth/captcha')
      .then((loaded) => {
        if (cancelled) return;
        setConfig(loaded);
        if (loaded.provider) report.current(null);
      })
      .catch(() => {});
    return () => {
      cancelled = true;
    };
  }, [resetKey]);

  if (!config?.provider) return null;
  if (failed) return <Alert severity="error">{t('The verification could not be loaded. Reload the page to try again.')}</Alert>;
  return config.provider === 'altcha' ? (
    <Altcha challenge={config.challenge} onAnswer={(answer) => report.current(answer)} onFail={() => setFailed(true)} />
  ) : (
    <Hosted provider={config.provider} siteKey={config.site_key} resetKey={resetKey} onAnswer={(answer) => report.current(answer)} onFail={() => setFailed(true)} />
  );
}

function Hosted({ provider, siteKey, resetKey, onAnswer, onFail }: { provider: keyof typeof SCRIPTS; siteKey: string; resetKey: number; onAnswer: (answer: string | null) => void; onFail: () => void }) {
  const element = useRef<HTMLDivElement>(null);
  const widget = useRef<{ api: WidgetApi; id: string | number } | null>(null);
  const dark = useTheme().palette.mode === 'dark';
  const callbacks = useRef({ onAnswer, onFail });
  callbacks.current = { onAnswer, onFail };

  useEffect(() => {
    let cancelled = false;
    loadScript(provider)
      .then((api) => {
        if (cancelled || !element.current) return;
        const id = api.render(element.current, {
          sitekey: siteKey,
          theme: dark ? 'dark' : 'light',
          callback: (answer: string) => callbacks.current.onAnswer(answer),
          'expired-callback': () => callbacks.current.onAnswer(null),
          'error-callback': () => callbacks.current.onAnswer(null),
        });
        widget.current = { api, id };
      })
      .catch(() => !cancelled && callbacks.current.onFail());
    return () => {
      cancelled = true;
      if (widget.current) {
        widget.current.api.remove?.(widget.current.id);
        widget.current = null;
      }
      if (element.current) element.current.replaceChildren();
    };
  }, [provider, siteKey, dark]);

  useEffect(() => {
    if (resetKey && widget.current) widget.current.api.reset(widget.current.id);
  }, [resetKey]);

  return <Box ref={element} sx={{ display: 'flex', justifyContent: 'center', minHeight: 65 }} />;
}

function Altcha({ challenge, onAnswer, onFail }: { challenge: AltchaChallenge; onAnswer: (answer: string) => void; onFail: () => void }) {
  const [done, setDone] = useState(false);
  const callbacks = useRef({ onAnswer, onFail });
  callbacks.current = { onAnswer, onFail };

  useEffect(() => {
    let cancelled = false;
    setDone(false);
    if (!crypto.subtle) {
      callbacks.current.onFail();
      return;
    }
    void solveAltcha(challenge, () => cancelled).then((answer) => {
      if (cancelled) return;
      if (!answer) {
        callbacks.current.onFail();
        return;
      }
      setDone(true);
      callbacks.current.onAnswer(answer);
    });
    return () => {
      cancelled = true;
    };
  }, [challenge]);

  return (
    <Stack direction="row" spacing={1} alignItems="center" role="status" sx={{ color: 'text.secondary' }}>
      {done ? <CheckCircle color="success" fontSize="small" /> : <CircularProgress size={18} />}
      <Typography variant="body2">{done ? t('Verified that you are not a robot') : t('Checking that you are not a robot…')}</Typography>
    </Stack>
  );
}
