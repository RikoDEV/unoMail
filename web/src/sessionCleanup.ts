import { setCsrfToken } from './api';
import { clearMailCache, closeCache } from './mail/cache';
import { clearPendingFiles } from './mail/pendingFiles';
import { lock } from './mail/pgp';
import { unloadPlugins } from './plugins';
import { resetPrefs } from './prefs';

/** Clear secrets synchronously, then remove asynchronous file storage. */
export function clearSensitiveSessionState(): Promise<void> {
  closeCache();
  lock();
  setCsrfToken('');
  clearMailCache();
  resetPrefs();
  unloadPlugins();
  return clearPendingFiles();
}
