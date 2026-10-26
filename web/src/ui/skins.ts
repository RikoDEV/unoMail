// Skins: named sets of design tokens that are turned into a Material UI theme. A skin is plain
// data (colours, corner radius, density, font), never CSS or code, so administrators can
// install custom ones without being able to inject anything into the page.
//
// The theme follows Material 3 Expressive: a tonal colour scheme generated from the accent
// (the 2025 colour spec), spring motion, and shapes that morph when pressed or selected. The
// numbers below are the Material 3 tokens (as published with Jetpack Compose).

import { argbFromHex, hexFromArgb, Hct, SchemeTonalSpot } from '@material/material-color-utilities';
import { alpha, createTheme, type Theme, type ThemeOptions } from '@mui/material';
import '@fontsource-variable/roboto-flex';

import { t } from '../i18n';
import { readableOn } from '../mail/extra';
import { type Images, type Part, type PartStyle, partStyles, sanitizeImages, sanitizeParts } from './skinParts';
export interface Skin {
  id: string;
  name: string;
  /** Forces light or dark; `auto` (default) follows the user's colour mode. */
  mode?: 'light' | 'dark' | 'auto';
  primary?: string;
  secondary?: string;
  tertiary?: string;
  error?: string;
  background?: string;
  paper?: string;
  text?: string;
  /** Background of selected and prominent items (the current folder, chosen chips and toggles, the Compose button); their text is black or white, whichever reads. */
  selected?: string;
  /** Corner radius in pixels (0 to 32). */
  radius?: number;
  density?: 'comfortable' | 'compact';
  /** Base spacing unit in pixels (4 to 12); overrides the density's default. */
  spacing?: number;
  /** Scale of the base font size (0.85 to 1.25). */
  fontScale?: number;
  font?: 'roboto' | 'system' | 'serif' | 'mono';
  /** Styles of named parts of the interface. */
  parts?: Partial<Record<Part, PartStyle>>;
  /** Background images (theme packages only). */
  images?: Images;
  imageFit?: 'cover' | 'contain' | 'tile';
}

/** The Material 3 colour roles that Material UI's palette has no place for. */
export interface M3Colors {
  surface: string;
  surfaceDim: string;
  surfaceBright: string;
  surfaceContainerLowest: string;
  surfaceContainerLow: string;
  surfaceContainer: string;
  surfaceContainerHigh: string;
  surfaceContainerHighest: string;
  onSurface: string;
  onSurfaceVariant: string;
  inverseSurface: string;
  inverseOnSurface: string;
  outline: string;
  outlineVariant: string;
  primaryContainer: string;
  onPrimaryContainer: string;
  secondaryContainer: string;
  onSecondaryContainer: string;
  tertiary: string;
  tertiaryContainer: string;
  onTertiaryContainer: string;
  errorContainer: string;
  onErrorContainer: string;
}

declare module '@mui/material/styles' {
  interface Palette {
    m3: M3Colors;
  }
  interface PaletteOptions {
    m3?: M3Colors;
  }
}

export const BUILT_IN_SKINS: Skin[] = [
  { id: 'material', name: t('Material You') },
  { id: 'classic', name: t('Classic'), primary: '#1a5fb4', radius: 4, font: 'system', density: 'compact' },
  { id: 'compact', name: t('Compact'), radius: 8, density: 'compact' },
  { id: 'paper', name: t('Paper'), mode: 'light', primary: '#5d4037', background: '#f4ecd8', paper: '#fbf5e6', text: '#3e2723', radius: 6, font: 'serif' },
  { id: 'midnight', name: t('Midnight'), mode: 'dark', primary: '#8ab4f8', background: '#0b0f17', paper: '#141a24', radius: 12 },
  { id: 'contrast', name: t('High contrast'), mode: 'dark', primary: '#ffff00', background: '#000000', paper: '#000000', text: '#ffffff', selected: '#ffff00', radius: 0, font: 'system' },
];

const FONTS: Record<NonNullable<Skin['font']>, string> = {
  roboto: '"Roboto Flex Variable", "Roboto Flex", Roboto, system-ui, -apple-system, "Segoe UI", sans-serif',
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
  for (const key of ['primary', 'secondary', 'tertiary', 'error', 'background', 'paper', 'text', 'selected'] as const) {
    const value = raw[key];
    if (typeof value === 'string' && COLOR.test(value)) skin[key] = value;
  }
  if (typeof raw.radius === 'number' && raw.radius >= 0 && raw.radius <= 32) skin.radius = raw.radius;
  if (typeof raw.spacing === 'number' && Number.isInteger(raw.spacing) && raw.spacing >= 4 && raw.spacing <= 12) skin.spacing = raw.spacing;
  if (typeof raw.fontScale === 'number' && raw.fontScale >= 0.85 && raw.fontScale <= 1.25) skin.fontScale = raw.fontScale;
  if (raw.density === 'comfortable' || raw.density === 'compact') skin.density = raw.density;
  if (raw.font === 'roboto' || raw.font === 'system' || raw.font === 'serif' || raw.font === 'mono') skin.font = raw.font;
  const parts = sanitizeParts(raw.parts);
  if (parts) skin.parts = parts;
  const images = sanitizeImages(raw.images);
  if (images) skin.images = images;
  if (raw.imageFit === 'cover' || raw.imageFit === 'contain' || raw.imageFit === 'tile') skin.imageFit = raw.imageFit;
  return skin;
}

/** Whether the skin renders dark, given the user's own preference. */
export function skinIsDark(skin: Skin, userPrefersDark: boolean): boolean {
  return skin.mode === 'dark' || (skin.mode !== 'light' && userPrefersDark);
}

/**
 * A Material 3 spring as a CSS easing: the motion of a unit mass from 0 to 1, sampled into
 * `linear()` points, and the time it takes to settle. `damping` below 1 overshoots.
 */
export function spring(damping: number, stiffness: number): { easing: string; duration: number } {
  const w0 = Math.sqrt(stiffness);
  const wd = w0 * Math.sqrt(Math.max(0, 1 - damping * damping));
  const at = (time: number) =>
    damping < 1
      ? 1 - Math.exp(-damping * w0 * time) * (Math.cos(wd * time) + ((damping * w0) / wd) * Math.sin(wd * time))
      : 1 - Math.exp(-w0 * time) * (1 + w0 * time);
  // Settled once the envelope is within 0.2% of the target.
  const duration = Math.log(500 * (damping < 1 ? 1 : 3)) / (damping * w0);
  const steps = 40;
  const points = Array.from({ length: steps + 1 }, (_, i) => +at((duration * i) / steps).toFixed(3));
  points[steps] = 1;
  return { easing: `linear(${points.join(', ')})`, duration: Math.round(duration * 1000) };
}

/** Material 3 Expressive motion scheme (damping ratio, stiffness). */
const MOTION = {
  fastSpatial: spring(0.6, 800),
  defaultSpatial: spring(0.8, 380),
  slowSpatial: spring(0.8, 200),
  fastEffects: spring(1, 3800),
  defaultEffects: spring(1, 1600),
};
const SPATIAL = `${MOTION.fastSpatial.duration}ms ${MOTION.fastSpatial.easing}`;
const EFFECTS = `${MOTION.fastEffects.duration}ms ${MOTION.fastEffects.easing}`;

/** Material 3 corner tokens. */
const CORNER = { extraSmall: 4, small: 8, medium: 12, large: 16, largeIncreased: 20, extraLarge: 28, extraLargeIncreased: 32 };

/** The tonal colour scheme for an accent colour (Material's "tonal spot", 2025 spec). */
export function colorScheme(seed: string, dark: boolean): M3Colors & { primary: string; onPrimary: string; secondary: string; onSecondary: string; error: string } {
  const scheme = new SchemeTonalSpot(Hct.fromInt(argbFromHex(seed)), dark, 0, '2025');
  const hex = (argb: number) => hexFromArgb(argb);
  return {
    primary: hex(scheme.primary),
    onPrimary: hex(scheme.onPrimary),
    secondary: hex(scheme.secondary),
    onSecondary: hex(scheme.onSecondary),
    error: hex(scheme.error),
    surface: hex(scheme.surface),
    surfaceDim: hex(scheme.surfaceDim),
    surfaceBright: hex(scheme.surfaceBright),
    surfaceContainerLowest: hex(scheme.surfaceContainerLowest),
    surfaceContainerLow: hex(scheme.surfaceContainerLow),
    surfaceContainer: hex(scheme.surfaceContainer),
    surfaceContainerHigh: hex(scheme.surfaceContainerHigh),
    surfaceContainerHighest: hex(scheme.surfaceContainerHighest),
    onSurface: hex(scheme.onSurface),
    onSurfaceVariant: hex(scheme.onSurfaceVariant),
    inverseSurface: hex(scheme.inverseSurface),
    inverseOnSurface: hex(scheme.inverseOnSurface),
    outline: hex(scheme.outline),
    outlineVariant: hex(scheme.outlineVariant),
    primaryContainer: hex(scheme.primaryContainer),
    onPrimaryContainer: hex(scheme.onPrimaryContainer),
    secondaryContainer: hex(scheme.secondaryContainer),
    onSecondaryContainer: hex(scheme.onSecondaryContainer),
    tertiary: hex(scheme.tertiary),
    tertiaryContainer: hex(scheme.tertiaryContainer),
    onTertiaryContainer: hex(scheme.onTertiaryContainer),
    errorContainer: hex(scheme.errorContainer),
    onErrorContainer: hex(scheme.onErrorContainer),
  };
}

type Components = ThemeOptions['components'];

/** Builds the theme for a skin. `seed` is the user's accent colour, used when the skin has none. */
export function buildTheme(skin: Skin, seed: string, userPrefersDark: boolean): Theme {
  const dark = skinIsDark(skin, userPrefersDark);
  const radius = skin.radius ?? 16;
  const compact = skin.density === 'compact';
  // Expressive shapes and springs need generous corners; skins with tight corners (Classic,
  // High contrast) keep a square, calm look but still get the tonal colours.
  const expressive = radius >= 12;
  const c = colorScheme(skin.primary ?? seed, dark);
  // A skin that names its own colours is taken at its word.
  const m3: M3Colors = {
    ...c,
    ...(skin.background ? { surfaceContainer: skin.background, surfaceContainerLow: skin.background, surfaceDim: skin.background } : {}),
    ...(skin.paper ? { surface: skin.paper, surfaceContainerLowest: skin.paper, surfaceContainerHigh: skin.paper, surfaceContainerHighest: skin.paper } : {}),
    ...(skin.text ? { onSurface: skin.text, onSurfaceVariant: skin.text } : {}),
    ...(skin.tertiary ? { tertiary: skin.tertiary } : {}),
    ...(skin.selected
      ? { secondaryContainer: skin.selected, onSecondaryContainer: readableOn(skin.selected), primaryContainer: skin.selected, onPrimaryContainer: readableOn(skin.selected) }
      : {}),
  };
  const options: ThemeOptions = {
    palette: {
      mode: dark ? 'dark' : 'light',
      // A skin's own accent gets the readable text colour MUI works out for it.
      primary: skin.primary ? { main: skin.primary } : { main: c.primary, contrastText: c.onPrimary },
      secondary: skin.secondary ? { main: skin.secondary } : { main: c.secondary, contrastText: c.onSecondary },
      error: { main: skin.error ?? c.error },
      // Pages sit on the surface container; the panes and cards on them are the surface.
      background: { default: skin.background ?? c.surfaceContainer, paper: skin.paper ?? c.surface },
      text: { primary: m3.onSurface, secondary: m3.onSurfaceVariant },
      divider: m3.outlineVariant,
      m3,
    },
    shape: { borderRadius: radius },
    spacing: skin.spacing ?? (compact ? 6 : 8),
    transitions: expressive
      ? {
          // Spatial movement (drawers, collapses) uses the non-bouncing effects springs; the
          // bouncy spatial spring is kept for shapes, which may overshoot without harm.
          easing: { easeInOut: MOTION.defaultEffects.easing, easeOut: MOTION.defaultEffects.easing, easeIn: 'cubic-bezier(0.3, 0, 0.8, 0.15)', sharp: MOTION.fastEffects.easing },
          duration: { shortest: 150, shorter: 200, short: 250, standard: 300, complex: 400, enteringScreen: 400, leavingScreen: 200 },
        }
      : {},
    typography: {
      fontFamily: FONTS[skin.font ?? 'roboto'],
      fontSize: Math.round((compact ? 13 : 14) * (skin.fontScale ?? 1) * 10) / 10,
      // Material 3 type scale, with the "emphasized" weights for headlines and titles.
      h1: { fontSize: '3.5625rem', lineHeight: 64 / 57, fontWeight: 400, letterSpacing: '-0.016em' },
      h2: { fontSize: '2.8125rem', lineHeight: 52 / 45, fontWeight: 400, letterSpacing: 0 },
      h3: { fontSize: '2.25rem', lineHeight: 44 / 36, fontWeight: 400, letterSpacing: 0 },
      h4: { fontSize: '1.75rem', lineHeight: 36 / 28, fontWeight: expressive ? 500 : 400, letterSpacing: 0 },
      h5: { fontSize: '1.5rem', lineHeight: 32 / 24, fontWeight: expressive ? 500 : 400, letterSpacing: 0 },
      h6: { fontSize: '1.375rem', lineHeight: 28 / 22, fontWeight: expressive ? 500 : 400, letterSpacing: 0 },
      subtitle1: { fontSize: '1rem', lineHeight: 1.5, fontWeight: expressive ? 600 : 500, letterSpacing: '0.009em' },
      subtitle2: { fontSize: '0.875rem', lineHeight: 20 / 14, fontWeight: expressive ? 600 : 500, letterSpacing: '0.007em' },
      button: { textTransform: 'none', fontWeight: 500, letterSpacing: '0.007em' },
      overline: { textTransform: 'none', fontSize: '0.75rem', fontWeight: 600, letterSpacing: '0.04em', lineHeight: 16 / 12 },
      caption: { letterSpacing: '0.03em' },
    },
  };
  // The component styles need the finished palette, so the theme is built twice.
  const base = createTheme(options);
  const styled = components(base, { radius, compact, expressive });
  // The skin's parts and images come last, over the component styles.
  const baseline = (styled?.MuiCssBaseline?.styleOverrides ?? {}) as Record<string, object>;
  const extra = partStyles(base, skin.parts, skin.images, skin.imageFit);
  return createTheme({
    ...options,
    components: { ...styled, MuiCssBaseline: { styleOverrides: { ...baseline, ...extra, body: { ...(baseline.body ?? {}), ...(extra.body ?? {}) } } } },
  });
}

/** Material 3 (Expressive) component styles. */
function components(theme: Theme, { radius, compact, expressive }: { radius: number; compact: boolean; expressive: boolean }): Components {
  const m3 = theme.palette.m3;
  // Corners scale down with the skin's own radius; at the default (16) they are the tokens.
  const corner = (token: number) => (expressive ? token : Math.min(token, radius));
  const full = expressive ? 999 : radius;
  // Shape changes spring; colours change with the quick, non-bouncing spring.
  const shapeMotion = expressive ? { transition: `border-radius ${SPATIAL}, background-color ${EFFECTS}, color ${EFFECTS}, box-shadow ${EFFECTS}, border-color ${EFFECTS}` } : {};
  const state = (color: string, opacity: number) => alpha(color, opacity);
  /** Button heights and the pressed corner, per size (Material 3 extra small, small, medium). */
  const buttonSizes = {
    small: { height: 32, px: 12, pressed: corner(CORNER.small), fontSize: '0.8125rem' },
    medium: { height: 40, px: 16, pressed: corner(CORNER.small), fontSize: '0.875rem' },
    large: { height: 56, px: 24, pressed: corner(CORNER.medium), fontSize: '1rem' },
  };
  return {
    MuiCssBaseline: { styleOverrides: { body: { fontVariationSettings: '"wdth" 100' } } },
    MuiPaper: { styleOverrides: { root: { backgroundImage: 'none' } } },
    MuiButton: {
      defaultProps: { disableElevation: true, ...(compact ? { size: 'small' as const } : {}) },
      styleOverrides: {
        root: ({ ownerState }) => {
          const size = buttonSizes[ownerState.size ?? 'medium'];
          return {
            minHeight: size.height,
            paddingInline: size.px,
            fontSize: size.fontSize,
            borderRadius: full,
            ...shapeMotion,
            ...(expressive ? { '&:active': { borderRadius: size.pressed } } : {}),
          };
        },
        outlined: { borderColor: m3.outlineVariant, '&:hover': { borderColor: m3.outline } },
        startIcon: { marginRight: 8 },
      },
    },
    MuiIconButton: {
      styleOverrides: {
        root: {
          ...shapeMotion,
          ...(expressive ? { '&:active': { borderRadius: CORNER.small } } : {}),
        },
      },
    },
    MuiFab: {
      defaultProps: { color: 'primary' },
      styleOverrides: {
        // Material 3 FAB: 56dp, the large corner, primary container colours and level 3 shadow.
        root: {
          height: 56,
          minHeight: 56,
          borderRadius: corner(CORNER.large),
          boxShadow: theme.shadows[3],
          textTransform: 'none',
          fontWeight: 600,
          fontSize: '0.9375rem',
          ...shapeMotion,
          '&:hover': { boxShadow: theme.shadows[4] },
          '&:active': { boxShadow: theme.shadows[3], ...(expressive ? { borderRadius: corner(CORNER.medium) } : {}) },
        },
        primary: { backgroundColor: m3.primaryContainer, color: m3.onPrimaryContainer, '&:hover': { backgroundColor: `color-mix(in srgb, ${m3.onPrimaryContainer} 8%, ${m3.primaryContainer})` } },
        sizeSmall: { width: 40, height: 40, minHeight: 40, borderRadius: corner(CORNER.medium) },
        extended: { height: 56, paddingInline: 20, gap: 12, borderRadius: corner(CORNER.large), '& .MuiSvgIcon-root': { marginRight: 0 } },
      },
    },
    // Connected button group: 2dp apart, round outer ends, small inner corners that tighten
    // when pressed; the selected button becomes fully round.
    MuiToggleButtonGroup: {
      styleOverrides: {
        root: { gap: 2, borderRadius: 0 },
        grouped: {
          border: 0,
          margin: 0,
          '&.MuiToggleButtonGroup-middleButton, &.MuiToggleButtonGroup-lastButton': { marginLeft: 0, borderLeft: 0 },
        },
        firstButton: { borderRadius: `${full}px ${corner(CORNER.small)}px ${corner(CORNER.small)}px ${full}px` },
        middleButton: { borderRadius: corner(CORNER.small) },
        lastButton: { borderRadius: `${corner(CORNER.small)}px ${full}px ${full}px ${corner(CORNER.small)}px` },
      },
    },
    MuiToggleButton: {
      styleOverrides: {
        root: ({ ownerState }) => ({
          textTransform: 'none',
          fontWeight: 500,
          gap: 6,
          border: 0,
          minHeight: ownerState.size === 'small' ? 32 : ownerState.size === 'large' ? 56 : 40,
          paddingBlock: 0,
          paddingInline: ownerState.size === 'small' ? 12 : 16,
          color: m3.onSecondaryContainer,
          backgroundColor: m3.secondaryContainer,
          ...shapeMotion,
          '&:hover': { backgroundColor: `color-mix(in srgb, ${m3.onSecondaryContainer} 8%, ${m3.secondaryContainer})` },
          '&:active': { borderRadius: `${corner(CORNER.extraSmall)}px` },
          '&.Mui-selected, &.Mui-selected:hover': { color: theme.palette.primary.contrastText, backgroundColor: theme.palette.primary.main, borderRadius: full },
          '&.Mui-disabled': { border: 0, backgroundColor: state(m3.onSurface, 0.1) },
        }),
      },
    },
    // Split button: the two halves 2dp apart, inner corners small, the menu half round when open.
    MuiButtonGroup: {
      defaultProps: { disableElevation: true },
      styleOverrides: {
        root: { gap: 2, borderRadius: 0, boxShadow: 'none' },
        grouped: { minWidth: 0, borderColor: 'transparent !important', ...shapeMotion },
        firstButton: { borderRadius: `${full}px ${corner(CORNER.extraSmall)}px ${corner(CORNER.extraSmall)}px ${full}px`, '&:active': { borderRadius: `${full}px ${corner(CORNER.small)}px ${corner(CORNER.small)}px ${full}px` } },
        middleButton: { borderRadius: corner(CORNER.extraSmall) },
        lastButton: { borderRadius: `${corner(CORNER.extraSmall)}px ${full}px ${full}px ${corner(CORNER.extraSmall)}px`, '&:active, &[aria-expanded="true"]': { borderRadius: full } },
      },
    },
    MuiChip: {
      styleOverrides: {
        root: { borderRadius: corner(CORNER.small), fontWeight: 500, ...shapeMotion },
        outlined: { borderColor: m3.outlineVariant },
        filled: ({ ownerState }) => (ownerState.color === 'default' || !ownerState.color ? { backgroundColor: m3.secondaryContainer, color: m3.onSecondaryContainer } : {}),
      },
    },
    MuiCard: {
      defaultProps: { elevation: 0 },
      styleOverrides: {
        root: ({ ownerState }) => ({
          borderRadius: corner(CORNER.extraLarge - 4),
          ...(ownerState.variant === 'outlined' ? { borderColor: m3.outlineVariant } : { backgroundColor: m3.surfaceContainerLow }),
        }),
      },
    },
    MuiDialog: {
      styleOverrides: { paper: { borderRadius: corner(CORNER.extraLarge), backgroundColor: m3.surfaceContainerHigh } },
    },
    MuiDialogTitle: { styleOverrides: { root: { fontSize: '1.5rem', lineHeight: 32 / 24, fontWeight: expressive ? 500 : 400, paddingTop: 24 } } },
    MuiDialogActions: { styleOverrides: { root: { padding: '16px 24px 20px', gap: 8 } } },
    MuiDrawer: { styleOverrides: { paper: { borderRadius: expressive ? `0 ${CORNER.large}px ${CORNER.large}px 0` : 0 } } },
    // Expressive menus: a rounded surface container, items with their own rounded shape, the
    // chosen item in the tertiary container colour.
    MuiPopover: { styleOverrides: { paper: { borderRadius: corner(CORNER.large), backgroundColor: m3.surfaceContainerHigh, boxShadow: theme.shadows[3] } } },
    MuiMenu: { styleOverrides: { list: { padding: 4 } } },
    MuiMenuItem: {
      styleOverrides: {
        root: {
          borderRadius: corner(CORNER.medium),
          minHeight: 44,
          marginBlock: 1,
          ...shapeMotion,
          // Concentric with the menu: its large corner less the 4dp list padding.
          '&.Mui-selected, &.Mui-selected:hover': { backgroundColor: m3.tertiaryContainer, color: m3.onTertiaryContainer, borderRadius: corner(CORNER.medium) },
          '& + .MuiDivider-root': { marginBlock: 4 },
        },
      },
    },
    // Headings inside menus share the menu's surface (they stay visible while a long list scrolls).
    MuiListSubheader: {
      styleOverrides: {
        root: {
          '.MuiMenu-list &': { backgroundColor: m3.surfaceContainer, borderRadius: corner(CORNER.medium), lineHeight: '36px', paddingInline: 12 },
        },
      },
    },
    // Tooltips and snackbars invert the page. The scheme's own inverse pair comes out as grey on
    // near-black in light mode, so the text and surface colours are swapped instead.
    MuiTooltip: {
      styleOverrides: {
        tooltip: { borderRadius: CORNER.extraSmall, backgroundColor: m3.onSurface, color: m3.surface, fontSize: '0.75rem', fontWeight: 400, padding: '4px 8px' },
        arrow: { color: m3.onSurface },
      },
    },
    MuiSnackbarContent: { styleOverrides: { root: { borderRadius: corner(CORNER.extraSmall), backgroundColor: m3.onSurface, color: m3.surface } } },
    MuiAlert: { styleOverrides: { root: { borderRadius: corner(CORNER.medium) } } },
    MuiTabs: { styleOverrides: { indicator: { height: 3, borderRadius: '3px 3px 0 0' } } },
    MuiTab: { styleOverrides: { root: { textTransform: 'none', fontWeight: 500, '&.Mui-selected': { fontWeight: 600 } } } },
    // Navigation items and lists: full pill, the selected one in the secondary container.
    MuiListItemButton: {
      styleOverrides: {
        root: {
          borderRadius: full,
          ...shapeMotion,
          '&.Mui-selected, &.active': {
            backgroundColor: m3.secondaryContainer,
            color: m3.onSecondaryContainer,
            fontWeight: 600,
            '& .MuiListItemIcon-root': { color: m3.onSecondaryContainer },
            '& .MuiListItemText-primary': { fontWeight: 600 },
            // The row's own buttons and counts (a folder's menu, its message count) follow its text.
            '& .MuiIconButton-root, & .MuiTypography-caption': { color: 'inherit' },
            // A skin whose selection is its accent colour would hide an accent badge in it: invert it.
            ...(m3.secondaryContainer.toLowerCase() === theme.palette.primary.main.toLowerCase() ? { '& .MuiBadge-colorPrimary': { backgroundColor: m3.onSecondaryContainer, color: m3.secondaryContainer } } : {}),
          },
          '&.Mui-selected:hover, &.active:hover': { backgroundColor: `color-mix(in srgb, ${m3.onSecondaryContainer} 8%, ${m3.secondaryContainer})` },
        },
      },
    },
    MuiListItemIcon: { styleOverrides: { root: { color: m3.onSurfaceVariant } } },
    MuiOutlinedInput: {
      styleOverrides: {
        root: { borderRadius: corner(CORNER.extraSmall) + (expressive ? 4 : 0) },
        notchedOutline: { borderColor: m3.outline },
      },
    },
    MuiTextField: { defaultProps: { size: 'small' } },
    MuiTableCell: { styleOverrides: { root: { borderColor: m3.outlineVariant }, head: { fontWeight: 600, color: m3.onSurfaceVariant } } },
    MuiDivider: { styleOverrides: { root: { borderColor: m3.outlineVariant } } },
    MuiBadge: { styleOverrides: { badge: { fontWeight: 600 } } },
    // Linear progress is drawn by progress.tsx; the circular one gets rounded ends.
    MuiCircularProgress: { styleOverrides: { circle: { strokeLinecap: 'round' } } },
    MuiSlider: expressive
      ? {
          // Expressive slider: a thick track and a slim upright handle with a gap around it.
          styleOverrides: {
            root: { height: 16 },
            rail: { borderRadius: 8, opacity: 1, backgroundColor: m3.secondaryContainer },
            track: { borderRadius: 8, border: 0 },
            thumb: {
              width: 4,
              height: 44,
              borderRadius: 2,
              boxShadow: `0 0 0 6px ${theme.palette.background.paper}`,
              '&::before': { boxShadow: 'none' },
              '&:hover, &.Mui-focusVisible, &.Mui-active': { boxShadow: `0 0 0 6px ${theme.palette.background.paper}`, width: 2 },
            },
          },
        }
      : {},
    MuiCheckbox: { styleOverrides: { root: { borderRadius: full } } },
    MuiSwitch: { styleOverrides: m3Switch(m3) },
  };
}

/**
 * Material 3 switches, a little more compact than the specification's 52×32: a 44×24 track
 * with a 2px outline when off and filled with the colour when on; the thumb grows from 12 to
 * 18px when switched on (22 while pressed). The small size keeps the proportions at 36×20.
 */
function m3Switch(m3: M3Colors): NonNullable<NonNullable<Components>['MuiSwitch']>['styleOverrides'] {
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
        color: m3.outline,
        transition: `transform ${SPATIAL}`,
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
        '&.Mui-disabled': { color: m3.outline, opacity: 0.38 },
        '&.Mui-disabled + .MuiSwitch-track': { opacity: 0.12 },
        '&.Mui-focusVisible .MuiSwitch-thumb': { outline: `2px solid ${tone.main}`, outlineOffset: 2 },
      };
    },
    thumb: { boxShadow: 'none', backgroundColor: 'currentColor', transition: `width ${SPATIAL}, height ${SPATIAL}` },
    track: ({ ownerState }) => ({
      borderRadius: size(ownerState).height / 2,
      opacity: 1,
      backgroundColor: m3.surfaceContainerHighest,
      border: `2px solid ${m3.outline}`,
      boxSizing: 'border-box',
    }),
  };
}
