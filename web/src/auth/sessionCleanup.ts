import { setCsrfToken } from '../lib/api';
import { clearMailCache, closeCache } from '../mail/cache';
import { clearPendingFiles } from '../mail/pendingFiles';
import { lock } from '../mail/pgp';
import { resetPlugins } from '../lib/plugins';
import { stopPackages } from '../plugins/host';
import { resetPrefs } from '../lib/prefs';

/** Clear secrets synchronously, then remove asynchronous file storage. */
export function clearSensitiveSessionState(): Promise<void> {
  closeCache();
  lock();
  setCsrfToken('');
  clearMailCache();
  resetPrefs();
  resetPlugins();
  stopPackages();
  return clearPendingFiles();
}
