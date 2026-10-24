import Key from '@mui/icons-material/Key';
import LanguageIcon from '@mui/icons-material/Language';
import { Alert, Box, Button, Card, CardContent, Divider, Link, MenuItem, Stack, TextField, Typography } from '@mui/material';
import { useEffect, useRef, useState, type FormEvent } from 'react';
import { useLocation, useNavigate, useSearchParams } from 'react-router-dom';
import { ApiError, get, post, type Account, errorText } from '../lib/api';
import { announceAccountChange, type SecondFactorChallenge, useAuth } from '../app';
import { Link as RouterLink } from 'react-router-dom';
import { Captcha } from './captcha';
import { autofillAvailable, forgetUnknownPasskey, type PasskeyAnswer, passkeysAvailable, type RequestOptions, signWithPasskey, wasDismissed } from './webauthn';

import { currentLanguage, LANGUAGES, setLanguage, t } from '../i18n';
import { Copyright, Logo, useTitle } from '../ui/shell';
/** The second step of a sign-in: a code from the authenticator app, a passkey, or a recovery code. */
function SecondStep({ challenge, onDone, onCancel }: { challenge: SecondFactorChallenge; onDone: (data: { account: Account; csrf_token: string }) => void; onCancel: () => void }) {
  const [mode, setMode] = useState<'totp' | 'recovery'>(challenge.methods.totp ? 'totp' : 'recovery');
  const [code, setCode] = useState('');
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [options, setOptions] = useState<RequestOptions | null>(challenge.passkey);
  const canPasskey = challenge.methods.passkey && passkeysAvailable();

  async function answer(body: Record<string, unknown>) {
    setBusy(true);
    setError('');
    try {
      onDone(await post<{ account: Account; csrf_token: string }>('/api/auth/second-factor', { token: challenge.token, ...body }));
    } catch (err) {
      if (err instanceof ApiError && err.status === 400) {
        onCancel();
        return;
      }
      setError(err instanceof ApiError && err.status === 429 ? t('Too many attempts. Please try again later.') : errorText(err, t('That did not work.')));
    } finally {
      setBusy(false);
    }
  }

  async function passkey() {
    setError('');
    try {
      let current = options;
      if (!current) {
        current = (await post<{ passkey: RequestOptions | null }>('/api/auth/second-factor/passkey', { token: challenge.token })).passkey;
        setOptions(current);
      }
      if (!current) return;
      const signed = await signWithPasskey(current);
      // Each challenge is good for one answer; the next try asks for a new one.
      setOptions(null);
      await answer({ passkey: signed });
    } catch (err) {
      setOptions(null);
      if (err instanceof DOMException) setError(t('The passkey was not used. Try again, or use another way.'));
      else if (!(err instanceof ApiError)) setError(errorText(err, t('The passkey did not work.')));
    }
  }

  return (
    <Stack
      component="form"
      spacing={2.5}
      onSubmit={(e) => {
        e.preventDefault();
        void answer(mode === 'totp' ? { code } : { recovery_code: code });
      }}
    >
      <Box>
        <Typography variant="h5" component="h1" sx={{ fontWeight: 600 }}>{t('2-step verification')}</Typography>
        <Typography sx={{ color: 'text.secondary' }}>{mode === 'totp' ? t('Enter the code from your authenticator app.') : t('Enter one of your recovery codes.')}</Typography>
      </Box>
      {error && <Alert severity="error">{error}</Alert>}
      {(challenge.methods.totp || challenge.methods.recovery) && (
        <TextField
          key={mode}
          label={mode === 'totp' ? t('Code') : t('Recovery code')}
          value={code}
          onChange={(e) => setCode(e.target.value)}
          autoFocus
          autoComplete="one-time-code"
          slotProps={{ htmlInput: mode === 'totp' ? { inputMode: 'numeric', maxLength: 7 } : { autoCapitalize: 'none', spellCheck: false } }}
        />
      )}
      {(challenge.methods.totp || challenge.methods.recovery) && (
        <Button type="submit" variant="contained" size="large" disabled={busy || !code.trim()}>
          {t('Verify')}
        </Button>
      )}
      {canPasskey && (
        <Button variant={challenge.methods.totp ? 'outlined' : 'contained'} size="large" startIcon={<Key />} onClick={() => void passkey()} disabled={busy}>
          {t('Use a passkey')}
        </Button>
      )}
      <Stack direction="row" spacing={2} sx={{ justifyContent: 'space-between' }}>
        {challenge.methods.recovery && mode === 'totp' && <Link component="button" type="button" onClick={() => { setMode('recovery'); setCode(''); }}>{t('Use a recovery code')}</Link>}
        {challenge.methods.totp && mode === 'recovery' && <Link component="button" type="button" onClick={() => { setMode('totp'); setCode(''); }}>{t('Use the authenticator app')}</Link>}
        <Link component="button" type="button" onClick={onCancel}>{t('Back')}</Link>
      </Stack>
    </Stack>
  );
}

/** The sign-in page. With `adding`, the user is signed in already and adds another account. */
export function Login({ adding = false }: { adding?: boolean }) {
  useTitle(adding ? t('Add another account') : t('Sign in'));
  const { login, completeLogin } = useAuth();
  const [challenge, setChallenge] = useState<SecondFactorChallenge | null>(null);
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [searchParams] = useSearchParams();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [sso, setSso] = useState<{ enabled: boolean; name?: string }>({ enabled: false });
  // The captcha's answer: undefined without a captcha, null until it is answered.
  const [captcha, setCaptcha] = useState<string | null | undefined>(undefined);
  const [captchaRound, setCaptchaRound] = useState(0);

  useEffect(() => {
    get<{ enabled: boolean; name?: string }>('/api/auth/oauth').then(setSso).catch(() => {});
  }, []);

  // A single sign-on attempt comes back here: the server holds its outcome (the reason it
  // failed, or the second step still to take), so nothing in the address can fake one.
  const ssoReturn = searchParams.get('sso') === '1';
  useEffect(() => {
    if (!ssoReturn) return;
    get<{ error?: string; second_factor?: SecondFactorChallenge }>('/api/auth/oauth/result')
      .then((outcome) => {
        if (outcome.second_factor) setChallenge(outcome.second_factor);
        else if (outcome.error) setError(outcome.error.slice(0, 300));
      })
      .catch(() => {});
  }, [ssoReturn]);

  // --- Signing in with a passkey alone ---
  // Whether this server and browser can sign in with passkeys (the server needs a host name).
  const [passkeys, setPasskeys] = useState(false);
  const waitingPasskey = useRef<AbortController | null>(null);
  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
      waitingPasskey.current?.abort();
    };
  }, []);

  /**
   * Signs in with a passkey. `autofill`: wait for the user to pick one in the address field's
   * suggestions; otherwise open the browser's passkey dialog right away.
   */
  async function passkeySignIn(autofill: boolean) {
    waitingPasskey.current?.abort();
    const controller = new AbortController();
    waitingPasskey.current = controller;
    let start: { token: string; options: RequestOptions };
    try {
      start = await get<{ token: string; options: RequestOptions }>('/api/auth/passkey');
    } catch {
      return;
    }
    if (!mounted.current || controller.signal.aborted) return;
    setPasskeys(true);
    let answer: PasskeyAnswer;
    try {
      answer = await signWithPasskey(start.options, { mediation: autofill ? 'conditional' : undefined, signal: controller.signal });
    } catch (err) {
      if (!wasDismissed(err)) setError(t('The passkey did not work.'));
      // A dismissed dialog leaves the autofill offer in place for another try.
      if (!autofill && mounted.current) void passkeySignIn(true);
      return;
    }
    setBusy(true);
    setError('');
    try {
      completeLogin(await post<{ account: Account; csrf_token: string }>('/api/auth/passkey', { token: start.token, credential: answer }));
      finished();
      return;
    } catch (err) {
      if (err instanceof ApiError && err.status === 404) {
        // Removed here but still on the device: ask the device to stop offering it.
        forgetUnknownPasskey(start.options.rpId, answer.id);
        setError(t('This passkey is not registered here any more. Sign in with your password.'));
      } else {
        setError(err instanceof ApiError && err.status === 429 ? t('Too many attempts. Please try again later.') : t('The passkey could not sign you in.'));
      }
    } finally {
      if (mounted.current) setBusy(false);
    }
    if (mounted.current) void passkeySignIn(true);
  }

  // Passkeys are offered in the address field's autofill where the browser can; elsewhere the
  // button below is the way in. Asking the server also tells whether passkeys work here at all.
  useEffect(() => {
    if (challenge || !passkeysAvailable()) return;
    let cancelled = false;
    void autofillAvailable().then((autofill) => {
      if (cancelled) return;
      if (autofill) void passkeySignIn(true);
      else get<{ token: string }>('/api/auth/passkey').then(() => !cancelled && setPasskeys(true)).catch(() => {});
    });
    return () => {
      cancelled = true;
      waitingPasskey.current?.abort();
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [challenge]);

  function finished() {
    if (adding) {
      // The new account is the current one now: start afresh with it, here and in other tabs.
      announceAccountChange();
      window.location.assign('/mail');
      return;
    }
    const from = (location.state as { from?: string } | null)?.from;
    // Only ever navigate to a path inside the application.
    navigate(from && from.startsWith('/') && !from.startsWith('//') ? from : '/mail', { replace: true });
  }

  async function submit(event: FormEvent) {
    event.preventDefault();
    // The password is used: the waiting passkey request would only get in the way.
    waitingPasskey.current?.abort();
    setBusy(true);
    setError('');
    try {
      const second = await login(email.trim(), password, captcha ?? undefined);
      if (second) {
        setChallenge(second);
        return;
      }
      finished();
    } catch (err) {
      if (err instanceof ApiError && err.status === 400 && err.message === 'captcha') setError(t('Complete the verification and try again.'));
      else setError(err instanceof ApiError && err.status === 429 ? t('Too many attempts. Please try again later.') : t('Incorrect e-mail address or password.'));
      // An answer signs in once: the next try needs a new one.
      if (captcha !== undefined) setCaptchaRound((round) => round + 1);
    } finally {
      setBusy(false);
    }
  }

  return (
    <Box sx={{ minHeight: '100vh', display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', p: 2 }}>
      <Card sx={{ width: '100%', maxWidth: 420, p: 2 }}>
        <CardContent>
          {challenge ? (
            <SecondStep
              challenge={challenge}
              onDone={(data) => {
                completeLogin(data);
                finished();
              }}
              onCancel={() => {
                setChallenge(null);
                setPassword('');
                setError(t('Enter your password again.'));
              }}
            />
          ) : (
          <Stack component="form" spacing={2.5} onSubmit={submit}>
            <Box>
              <Stack direction="row" spacing={1.5} sx={{ alignItems: 'center', mb: 0.5 }}>
                <Logo size={44} />
                <Typography variant="h4" component="h1" color="primary" sx={{ fontWeight: 600 }}>
                  {t('unoMail')}
                </Typography>
              </Stack>
              <Typography sx={{ color: 'text.secondary' }}>{adding ? t('Add another account') : t('Sign in to your mailbox')}</Typography>
            </Box>
            {error && <Alert severity="error">{error}</Alert>}
            {/* Not type="email": browsers refuse internationalized addresses in such fields. */}
            <TextField label={t('E-mail address')} type="text" slotProps={{ htmlInput: { inputMode: 'email', autoCapitalize: 'none', spellCheck: false } }} autoComplete="username webauthn" value={email} onChange={(e) => setEmail(e.target.value)} required autoFocus size="medium" />
            <TextField label={t('Password')} type="password" autoComplete="current-password" value={password} onChange={(e) => setPassword(e.target.value)} required size="medium" />
            <Captcha onAnswer={setCaptcha} resetKey={captchaRound} />
            <Button type="submit" variant="contained" size="large" disabled={busy || captcha === null}>
              {t('Sign in')}
            </Button>
            {passkeys && (
              <Button variant="outlined" size="large" startIcon={<Key />} onClick={() => void passkeySignIn(false)} disabled={busy}>
                {t('Sign in with a passkey')}
              </Button>
            )}
            {sso.enabled && (
              <>
                <Divider>{t('or')}</Divider>
                {/* A full page navigation: the provider's sign-in page cannot be shown inside ours. */}
                <Button component="a" href="/api/auth/oauth/start" variant="outlined" size="large">
                  {sso.name || t('Single sign-on')}
                </Button>
              </>
            )}
            {adding && (
              <Link component={RouterLink} to="/mail" sx={{ textAlign: 'center' }}>
                {t('Cancel')}
              </Link>
            )}
          </Stack>
          )}
        </CardContent>
      </Card>
      {/* Before signing in there is no account preference yet: the choice is kept on this device. */}
      {/* Quiet, like a link: it is there when wanted and does not compete with signing in. */}
      <TextField
        select
        size="small"
        variant="standard"
        value={currentLanguage()}
        onChange={(e) => setLanguage(e.target.value)}
        slotProps={{
          input: { disableUnderline: true, startAdornment: <LanguageIcon sx={{ fontSize: 18, mr: 0.75, color: 'text.secondary' }} /> },
          select: { SelectDisplayProps: { 'aria-label': t('Language') } as React.HTMLAttributes<HTMLDivElement> },
        }}
        sx={{
          mt: 2,
          '& .MuiInputBase-root': { px: 1.25, py: 0.25, borderRadius: 999, color: 'text.secondary', fontSize: 14, transition: 'background-color 150ms' },
          '& .MuiInputBase-root:hover, & .MuiInputBase-root.Mui-focused': { bgcolor: 'action.hover' },
          '& .MuiSelect-select': { bgcolor: 'transparent !important', py: 0.5 },
          '& .MuiSelect-icon': { color: 'text.secondary' },
        }}
      >
        {LANGUAGES.map((language) => (
          <MenuItem key={language.code} value={language.code} lang={language.code}>
            {language.name}
          </MenuItem>
        ))}
      </TextField>
      <Copyright placement="login" sx={{ mt: 1 }} />
    </Box>
  );
}
