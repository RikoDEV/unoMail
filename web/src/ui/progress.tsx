import { alpha, Box, keyframes, type SxProps, type Theme } from '@mui/material';

// Material 3 Expressive linear progress: the active indicator and the track are separate rounded
// segments with a gap between them, and a determinate track ends in a stop indicator. The theme
// alone cannot draw this (the track's start depends on the value), hence a component of its own.

type Color = 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';

interface Props {
  variant?: 'determinate' | 'indeterminate';
  /** 0–100, for a determinate indicator. */
  value?: number;
  color?: Color;
  sx?: SxProps<Theme>;
  'aria-label'?: string;
}

const GAP = 4;

// One active segment travels across; the track pieces either side follow it at a fixed gap
// (a negative width is clamped to none while the segment enters).
const WIDTH = 40;
const bar = keyframes`
  0% { left: -${WIDTH}%; }
  70%, 100% { left: 100%; }
`;
const before = keyframes`
  0% { width: calc(-${WIDTH}% - ${GAP}px); }
  70%, 100% { width: calc(100% - ${GAP}px); }
`;
const after = keyframes`
  0% { left: ${GAP}px; }
  70%, 100% { left: calc(100% + ${WIDTH}% + ${GAP}px); }
`;

export function LinearProgress({ variant = 'indeterminate', value = 0, color = 'primary', sx, 'aria-label': label }: Props) {
  const active = (theme: Theme) => theme.palette[color].main;
  const track = (theme: Theme) => (color === 'primary' ? theme.palette.m3.secondaryContainer : alpha(theme.palette[color].main, 0.24));
  const segment = { position: 'absolute', top: 0, bottom: 0, borderRadius: 999 } as const;
  const shown = Math.max(0, Math.min(100, value));
  return (
    <Box
      role="progressbar"
      aria-label={label}
      {...(variant === 'determinate' ? { 'aria-valuenow': Math.round(shown), 'aria-valuemin': 0, 'aria-valuemax': 100 } : {})}
      sx={[{ position: 'relative', height: 4, overflow: 'hidden', borderRadius: 999 }, ...(Array.isArray(sx) ? sx : [sx])]}
    >
      {variant === 'determinate' ? (
        <>
          {shown > 0 && <Box sx={{ ...segment, left: 0, width: `${shown}%`, bgcolor: active, transition: 'width .3s ease' }} />}
          {shown < 100 && (
            <Box sx={{ ...segment, right: 0, left: shown > 0 ? `calc(${shown}% + ${GAP}px)` : 0, bgcolor: track, transition: 'left .3s ease' }}>
              {/* The stop indicator: a dot of the active colour at the track's end. */}
              <Box sx={{ position: 'absolute', right: 0, top: '50%', width: 4, height: 4, transform: 'translateY(-50%)', borderRadius: '50%', bgcolor: active }} />
            </Box>
          )}
        </>
      ) : (
        <Box sx={{ '& > *': { animationDuration: '1.8s', animationTimingFunction: 'cubic-bezier(.4,0,.2,1)', animationIterationCount: 'infinite' }, '@media (prefers-reduced-motion: reduce)': { '& > *': { animationDuration: '6s' } } }}>
          <Box sx={{ ...segment, left: 0, bgcolor: track, animationName: `${before}` }} />
          <Box sx={{ ...segment, width: `${WIDTH}%`, bgcolor: active, animationName: `${bar}` }} />
          <Box sx={{ ...segment, width: '100%', bgcolor: track, animationName: `${after}` }} />
        </Box>
      )}
    </Box>
  );
}
