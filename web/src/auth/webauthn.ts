// Passkeys in the browser: the server's options (base64url text) turned into what the
// WebAuthn API takes, and its answers back into text for the server.

import { t } from '../i18n';

function fromB64url(text: string): ArrayBuffer {
  const base64 = text.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(text.length / 4) * 4, '=');
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function toB64url(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

export const passkeysAvailable = () => typeof window !== 'undefined' && 'PublicKeyCredential' in window && Boolean(navigator.credentials);

/** Whether the browser can offer passkeys in the address field's autofill. */
export async function autofillAvailable(): Promise<boolean> {
  if (!passkeysAvailable()) return false;
  try {
    return (await PublicKeyCredential.isConditionalMediationAvailable?.()) === true;
  } catch {
    return false;
  }
}

type Descriptor = { type: 'public-key'; id: string; transports?: AuthenticatorTransport[] };

export interface CreationOptions {
  challenge: string;
  rp: { id: string; name: string };
  user: { id: string; name: string; displayName: string };
  pubKeyCredParams: { type: 'public-key'; alg: number }[];
  timeout?: number;
  attestation?: AttestationConveyancePreference;
  authenticatorSelection?: AuthenticatorSelectionCriteria;
  excludeCredentials?: Descriptor[];
  extensions?: AuthenticationExtensionsClientInputs;
}

export interface RequestOptions {
  challenge: string;
  rpId: string;
  timeout?: number;
  userVerification?: UserVerificationRequirement;
  allowCredentials?: Descriptor[];
}

const descriptors = (list: Descriptor[] = []) => list.map((d) => ({ type: d.type, id: fromB64url(d.id), ...(d.transports ? { transports: d.transports } : {}) }));

/** The user dismissed the browser's dialog, or the request was aborted: not an error to show. */
export function wasDismissed(err: unknown): boolean {
  return err instanceof DOMException && (err.name === 'NotAllowedError' || err.name === 'AbortError');
}

/** Registers a new passkey; returns the answer for the server. */
export async function createPasskey(options: CreationOptions): Promise<{ clientDataJSON: string; attestationObject: string; transports: string[]; discoverable?: boolean }> {
  const credential = (await navigator.credentials.create({
    publicKey: {
      ...options,
      challenge: fromB64url(options.challenge),
      user: { ...options.user, id: fromB64url(options.user.id) },
      excludeCredentials: descriptors(options.excludeCredentials),
    },
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error(t('No passkey was created'));
  const response = credential.response as AuthenticatorAttestationResponse;
  const transports = typeof response.getTransports === 'function' ? response.getTransports() : [];
  // credProps tells whether the passkey lives on the authenticator (signs in without an address).
  const props = (credential.getClientExtensionResults() as { credProps?: { rk?: boolean } }).credProps;
  return { clientDataJSON: toB64url(response.clientDataJSON), attestationObject: toB64url(response.attestationObject), transports, discoverable: props?.rk };
}

export interface PasskeyAnswer {
  id: string;
  clientDataJSON: string;
  authenticatorData: string;
  signature: string;
  userHandle?: string;
}

/**
 * Signs a challenge with a passkey. With `mediation: 'conditional'` the browser waits for the
 * user to pick a passkey from the address field's autofill instead of opening a dialog.
 */
export async function signWithPasskey(options: RequestOptions, extra: { mediation?: CredentialMediationRequirement; signal?: AbortSignal } = {}): Promise<PasskeyAnswer> {
  const credential = (await navigator.credentials.get({
    publicKey: { ...options, challenge: fromB64url(options.challenge), allowCredentials: descriptors(options.allowCredentials) },
    ...(extra.mediation ? { mediation: extra.mediation } : {}),
    ...(extra.signal ? { signal: extra.signal } : {}),
  })) as PublicKeyCredential | null;
  if (!credential) throw new Error(t('No passkey was used'));
  const response = credential.response as AuthenticatorAssertionResponse;
  return {
    id: toB64url(credential.rawId),
    clientDataJSON: toB64url(response.clientDataJSON),
    authenticatorData: toB64url(response.authenticatorData),
    signature: toB64url(response.signature),
    ...(response.userHandle ? { userHandle: toB64url(response.userHandle) } : {}),
  };
}

// The Signal API (WebAuthn Level 3) lets the site tell the passkey provider which passkeys it
// no longer accepts, so they stop being offered. Browsers without it simply skip this.
type Signals = {
  signalUnknownCredential?: (options: { rpId: string; credentialId: string }) => Promise<void>;
  signalAllAcceptedCredentials?: (options: { rpId: string; userId: string; allAcceptedCredentialIds: string[] }) => Promise<void>;
};

/** Tells the passkey provider that this site does not know a passkey (any more). */
export function forgetUnknownPasskey(rpId: string, credentialId: string) {
  const api = (typeof PublicKeyCredential === 'undefined' ? undefined : PublicKeyCredential) as Signals | undefined;
  void api?.signalUnknownCredential?.({ rpId, credentialId }).catch(() => {});
}

/** Tells the passkey provider which of the user's passkeys this site still accepts. */
export function keepOnlyAcceptedPasskeys(signal: { rpId: string; userId: string; allAcceptedCredentialIds: string[] } | null | undefined) {
  const api = (typeof PublicKeyCredential === 'undefined' ? undefined : PublicKeyCredential) as Signals | undefined;
  if (signal) void api?.signalAllAcceptedCredentials?.(signal).catch(() => {});
}
