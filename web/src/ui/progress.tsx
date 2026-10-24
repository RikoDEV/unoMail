import { alpha, Box, keyframes, type SxProps, type Theme } from '@mui/material';

// Material 3 Expressive linear progress: the active indicator is a wave and the track a flat,
// rounded segment beside it with a gap between them; a determinate track ends in a stop
// indicator. The theme alone cannot draw this (the track's start depends on the value), hence a
// component of its own.

type Color = 'primary' | 'secondary' | 'error' | 'warning' | 'info' | 'success';

interface Props {
  variant?: 'determinate' | 'indeterminate';
  /** 0–100, for a determinate indicator. */
  value?: number;
  color?: Color;
  /** Stroke width of the wave and height of the track, in pixels. */
  thickness?: number;
  sx?: SxProps<Theme>;
  'aria-label'?: string;
}

const GAP = 4;
const WAVELENGTH = 40;
const AMPLITUDE = 3;

/** One wavelength of the wave, used as a repeating mask over the active colour. */
function waveMask(thickness: number) {
  const height = thickness + AMPLITUDE * 2;
  const mid = height / 2;
  // A quadratic curve with its control point at twice the amplitude peaks at the amplitude. The
  // path runs half a wavelength past each edge, so neighbouring tiles join without a seam.
  const half = WAVELENGTH / 2;
  const path = `M${-half} ${mid} Q${-half / 2} ${mid + AMPLITUDE * 2} 0 ${mid} T${half} ${mid} T${WAVELENGTH} ${mid} T${WAVELENGTH + half} ${mid}`;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="${WAVELENGTH}" height="${height}"><path d="${path}" fill="none" stroke="#000" stroke-width="${thickness}"/></svg>`;
  return `url("data:image/svg+xml,${encodeURIComponent(svg)}")`;
}

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

export function LinearProgress({ variant = 'indeterminate', value = 0, color = 'primary', thickness = 4, sx, 'aria-label': label }: Props) {
  const active = (theme: Theme) => theme.palette[color].main;
  const track = (theme: Theme) => (color === 'primary' ? theme.palette.m3.secondaryContainer : alpha(theme.palette[color].main, 0.24));
  const mask = waveMask(thickness);
  // The flat track is as thick as the wave's stroke and sits on its centre line.
  const flat = { position: 'absolute', top: AMPLITUDE, height: thickness, borderRadius: 999 } as const;
  const wave = {
    position: 'absolute', top: 0, bottom: 0, bgcolor: active,
    maskImage: mask, maskRepeat: 'repeat-x', maskSize: `${WAVELENGTH}px 100%`,
  } as const;
  const shown = Math.max(0, Math.min(100, value));
  return (
    <Box
      role="progressbar"
      aria-label={label}
      {...(variant === 'determinate' ? { 'aria-valuenow': Math.round(shown), 'aria-valuemin': 0, 'aria-valuemax': 100 } : {})}
      sx={[{ position: 'relative', height: thickness + AMPLITUDE * 2, overflow: 'hidden' }, ...(Array.isArray(sx) ? sx : [sx])]}
    >
      {variant === 'determinate' ? (
        <>
          {/* Never thinner than the stroke, so a tiny non-zero value still differs from none. */}
          {shown > 0 && <Box sx={{ ...wave, left: 0, width: `max(${thickness}px, ${shown}%)`, transition: 'width .3s ease' }} />}
          {shown < 100 && (
            <Box sx={{ ...flat, right: 0, left: shown > 0 ? `calc(max(${thickness}px, ${shown}%) + ${GAP}px)` : 0, bgcolor: track, transition: 'left .3s ease' }}>
              {/* The stop indicator: a dot of the active colour at the track's end. */}
              <Box sx={{ position: 'absolute', right: 0, top: 0, width: thickness, height: thickness, borderRadius: '50%', bgcolor: active }} />
            </Box>
          )}
        </>
      ) : (
        <Box sx={{ '& > *': { animationDuration: '1.8s', animationTimingFunction: 'cubic-bezier(.4,0,.2,1)', animationIterationCount: 'infinite' }, '@media (prefers-reduced-motion: reduce)': { '& > *': { animationDuration: '6s' } } }}>
          <Box sx={{ ...flat, left: 0, bgcolor: track, animationName: `${before}` }} />
          <Box sx={{ ...wave, width: `${WIDTH}%`, animationName: `${bar}` }} />
          <Box sx={{ ...flat, width: '100%', bgcolor: track, animationName: `${after}` }} />
        </Box>
      )}
    </Box>
  );
}
