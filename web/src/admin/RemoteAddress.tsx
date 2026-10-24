import Public from '@mui/icons-material/Public';
import { Box, Stack, Tooltip, Typography } from '@mui/material';

import { t } from '../i18n';

// Each flag is a separate file fetched only when shown; the module holds just their addresses
// (the library's stylesheet would load every flag's rules up front).
const FLAGS = import.meta.glob<string>('../../node_modules/flag-icons/flags/4x3/*.svg', { eager: true, query: '?url&no-inline', import: 'default' });
const flagUrl = (code: string) => FLAGS[`../../node_modules/flag-icons/flags/4x3/${code.toLowerCase()}.svg`];

let countryNames: Intl.DisplayNames | null = null;
function countryName(code: string): string {
  try {
    countryNames ??= new Intl.DisplayNames(undefined, { type: 'region' });
    return countryNames.of(code) ?? code;
  } catch {
    return code;
  }
}

/** The flag of a country given its two-letter code; a globe when the country is unknown. */
function Flag({ country }: { country?: string | null }) {
  const code = country && /^[A-Za-z]{2}$/.test(country) ? country.toUpperCase() : null;
  const url = code ? flagUrl(code) : undefined;
  if (!code || !url) {
    return (
      <Tooltip title={t('Country unknown')}>
        <Public fontSize="small" color="disabled" aria-label={t('Country unknown')} sx={{ width: 20, height: 15 }} />
      </Tooltip>
    );
  }
  return (
    <Tooltip title={countryName(code)}>
      <Box component="img" src={url} alt={countryName(code)} data-country={code} loading="lazy" sx={{ width: 20, height: 15, objectFit: 'cover', borderRadius: '2px', flexShrink: 0, boxShadow: '0 0 0 1px rgba(128,128,128,.35)' }} />
    </Tooltip>
  );
}

/** A remote address with its country flag and, when known, its reverse DNS name. */
export function RemoteAddress({ address, rdns, country }: { address: string; rdns?: string | null; country?: string | null }) {
  return (
    <Stack direction="row" spacing={1} sx={{ alignItems: 'center', minWidth: 0 }}>
      <Flag country={country} />
      <Box sx={{ minWidth: 0 }}>
        {/* An IPv4 address stays on one line; only the long IPv6 ones may break. */}
        <Typography variant="body2" sx={{ fontFamily: 'monospace', ...(address.includes(':') ? { wordBreak: 'break-all' } : { whiteSpace: 'nowrap' }) }}>
          {address}
        </Typography>
        {rdns && (
          <Typography variant="caption" sx={{ color: 'text.secondary', display: 'block', wordBreak: 'break-all' }}>
            {rdns}
          </Typography>
        )}
      </Box>
    </Stack>
  );
}
