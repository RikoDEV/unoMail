// Skins: named sets of design tokens that are turned into a Material UI theme. A skin is plain
// data (colours, corner radius, density, font), never CSS or code, so administrators can
// install custom ones without being able to inject anything into the page.

import { createTheme, lighten, type Theme } from '@mui/material';

import { t } from './i18n';
export interface Skin {
  id: string;
  name: string;
  /** Forces light or dark; `auto` (default) follows the user's colour mode. */
  mode?: 'light' | 'dark' | 'auto';
  primary?: string;
  secondary?: string;
  background?: string;
  paper?: string;
  text?: string;
  /** Corner radius in pixels (0 to 32). */
  radius?: number;
  density?: 'comfortable' | 'compact';
  font?: 'roboto' | 'system' | 'serif' | 'mono';
}

export const BUILT_IN_SKINS: Skin[] = [
  { id: 'material', name: t('Material You') },
  { id: 'classic', name: t('Classic'), primary: '#1a5fb4', radius: 4, font: 'system', density: 'compact' },
  { id: 'compact', name: t('Compact'), radius: 8, density: 'compact' },
  { id: 'paper', name: t('Paper'), mode: 'light', primary: '#5d4037', background: '#f4ecd8', paper: '#fbf5e6', text: '#3e2723', radius: 6, font: 'serif' },
  { id: 'midnight', name: t('Midnight'), mode: 'dark', primary: '#8ab4f8', background: '#0b0f17', paper: '#141a24', radius: 12 },
  { id: 'contrast', name: t('High contrast'), mode: 'dark', primary: '#ffff00', background: '#000000', paper: '#000000', text: '#ffffff', radius: 0, font: 'system' },
];

const FONTS: Record<NonNullable<Skin['font']>, string> = {
  roboto: '"Roboto Flex", Roboto, system-ui, -apple-system, "Segoe UI", sans-serif',
  system: 'system-ui, -apple-system, "Segoe UI", sans-serif',
  serif: 'Georgia, "Times New Roman", serif',
  mono: 'ui-monospace, "Cascadia Mono", Consolas, monospace',
};

const COLOR = /^#[0-9a-f]{6}$/i;

/** Keeps only well-formed tokens of a skin received from the server. */
export function sanitizeSkin(input: unknown): Skin | null {
  if (!input || typeof input !== 'object') return null;
  const raw = input as Record<string, unknown>;
  if (typeof raw.id !== 'string' || typeof raw.name !== 'string' || !/^[a-z0-9-]{1,40}$/.test(raw.id)) return null;
  const skin: Skin = { id: raw.id, name: raw.name.slice(0, 60) };
  if (raw.mode === 'light' || raw.mode === 'dark' || raw.mode === 'auto') skin.mode = raw.mode;
  for (const key of ['primary', 'secondary', 'background', 'paper', 'text'] as const) {
    const value = raw[key];
    if (typeof value === 'string' && COLOR.test(value)) skin[key] = value;
  }
  if (typeof raw.radius === 'number' && raw.radius >= 0 && raw.radius <= 32) skin.radius = raw.radius;
  if (raw.density === 'comfortable' || raw.density === 'compact') skin.density = raw.density;
  if (raw.font === 'roboto' || raw.font === 'system' || raw.font === 'serif' || raw.font === 'mono') skin.font = raw.font;
  return skin;
}

/** Whether the skin renders dark, given the user's own preference. */
export function skinIsDark(skin: Skin, userPrefersDark: boolean): boolean {
  return skin.mode === 'dark' || (skin.mode !== 'light' && userPrefersDark);
}

/** Builds the theme for a skin. `seed` is the user's accent colour, used when the skin has none. */
export function buildTheme(skin: Skin, seed: string, userPrefersDark: boolean): Theme {
  const dark = skinIsDark(skin, userPrefersDark);
  const radius = skin.radius ?? 16;
  const compact = skin.density === 'compact';
  // Rounded "pill" shapes only make sense with generous corners.
  const pill = radius >= 12 ? 999 : radius;
  const defaults = dark ? { default: '#141218', paper: '#1d1b20' } : { default: '#f7f2fa', paper: '#fffbfe' };
  // An accent chosen for light surfaces is too dark to read on dark ones: on a dark theme the
  // user's accent colour is used in a lighter tone (as Material's dark schemes do). A skin that
  // names its own primary colour is taken at its word.
  const accent = skin.primary ?? (dark ? lighten(seed, 0.55) : seed);
  return createTheme({
    palette: {
      mode: dark ? 'dark' : 'light',
      primary: { main: accent },
      ...(skin.secondary ? { secondary: { main: skin.secondary } } : {}),
      background: { default: skin.background ?? defaults.default, paper: skin.paper ?? defaults.paper },
      // Secondary text slightly brighter than the default on dark surfaces, for legibility.
      ...(skin.text ? { text: { primary: skin.text } } : dark ? { text: { primary: '#ece6f0', secondary: '#cac4d0' } } : {}),
      ...(dark ? { divider: 'rgba(255,255,255,0.16)' } : {}),
    },
    shape: { borderRadius: radius },
    spacing: compact ? 6 : 8,
    typography: { fontFamily: FONTS[skin.font ?? 'roboto'], fontSize: compact ? 13 : 14, button: { textTransform: 'none', fontWeight: 500 } },
    components: {
      MuiButton: { styleOverrides: { root: { borderRadius: pill } }, defaultProps: compact ? { size: 'small' } : {} },
      MuiPaper: { styleOverrides: { root: { backgroundImage: 'none' } } },
      MuiCard: { defaultProps: { elevation: 0 }, styleOverrides: { root: { borderRadius: Math.min(radius * 1.5, 24) } } },
      MuiDialog: { styleOverrides: { paper: { borderRadius: Math.min(radius * 1.75, 28) } } },
      MuiListItemButton: { styleOverrides: { root: { borderRadius: pill } } },
      MuiTextField: { defaultProps: { size: 'small' } },
      MuiTableCell: { styleOverrides: { head: { fontWeight: 600 } } },
      MuiSwitch: { styleOverrides: m3Switch(dark) },
    },
  });
}

/**
 * Material 3 switches, a little more compact than the specification's 52×32: a 44×24 track
 * with a 2px outline when off and filled with the colour when on; the thumb grows from 12 to
 * 18px when switched on (22 while pressed). The small size keeps the proportions at 36×20.
 */
function m3Switch(dark: boolean): NonNullable<NonNullable<NonNullable<Parameters<typeof createTheme>[0]>['components']>['MuiSwitch']>['styleOverrides'] {
  // Material 3 outline and surface-container-highest tones.
  const outline = dark ? '#938f99' : '#79747e';
  const surface = dark ? '#36343b' : '#e6e0e9';
  const sizes = {
    medium: { width: 44, height: 24, off: 12, on: 18, pressed: 22 },
    small: { width: 36, height: 20, off: 10, on: 14, pressed: 18 },
  };
  const size = (ownerState: { size?: string }) => (ownerState.size === 'small' ? sizes.small : sizes.medium);
  return {
    root: ({ ownerState }) => {
      const s = size(ownerState);
      return { width: s.width, height: s.height, padding: 0, margin: 6, overflow: 'visible' };
    },
    switchBase: ({ theme, ownerState }) => {
      const s = size(ownerState);
      const tone = theme.palette[ownerState.color && ownerState.color !== 'default' ? ownerState.color : 'primary'];
      return {
        padding: 0,
        top: 0,
        left: 0,
        width: s.height,
        height: s.height,
        color: outline,
        '&:hover': { backgroundColor: theme.palette.action.hover },
        '& .MuiSwitch-thumb': { width: s.off, height: s.off },
        '&:active .MuiSwitch-thumb': { width: s.pressed, height: s.pressed },
        '&.Mui-checked': {
          transform: `translateX(${s.width - s.height}px)`,
          color: tone.contrastText,
          '& .MuiSwitch-thumb': { width: s.on, height: s.on },
          '&:active .MuiSwitch-thumb': { width: s.pressed, height: s.pressed },
          '& + .MuiSwitch-track': { backgroundColor: tone.main, borderColor: tone.main, opacity: 1 },
        },
        '&.Mui-disabled': { color: outline, opacity: 0.38 },
        '&.Mui-disabled + .MuiSwitch-track': { opacity: 0.12 },
        '&.Mui-focusVisible .MuiSwitch-thumb': { outline: `2px solid ${tone.main}`, outlineOffset: 2 },
      };
    },
    thumb: { boxShadow: 'none', backgroundColor: 'currentColor', transition: 'width 150ms, height 150ms' },
    track: ({ ownerState }) => ({
      borderRadius: size(ownerState).height / 2,
      opacity: 1,
      backgroundColor: surface,
      border: `2px solid ${outline}`,
      boxSizing: 'border-box',
    }),
  };
}
