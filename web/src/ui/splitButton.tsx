// Material 3 split button: an action and the menu of its options, as two joined segments.
// The segments are 2dp apart with small inner corners and fully round outer ones; the trailing
// arrow turns over while the menu is open.

import ExpandMore from '@mui/icons-material/ExpandMore';
import { Box, Button, type ButtonProps, Menu } from '@mui/material';
import { useState, type ReactNode } from 'react';

const INNER_CORNER = 4;

interface SplitButtonProps {
  /** Content of the leading segment (text, or an icon in compact layouts). */
  children: ReactNode;
  onClick: () => void;
  /** Accessible name of the trailing segment, which opens the menu. */
  menuLabel: string;
  /** The menu's items; called with a function that closes the menu. */
  menu: (close: () => void) => ReactNode;
  variant?: ButtonProps['variant'];
  size?: ButtonProps['size'];
  startIcon?: ReactNode;
  disabled?: boolean;
  /** Accessible name of the leading segment when it shows an icon only. */
  'aria-label'?: string;
}

export function SplitButton({ children, onClick, menuLabel, menu, variant = 'outlined', size, startIcon, disabled, 'aria-label': ariaLabel }: SplitButtonProps) {
  const [anchor, setAnchor] = useState<HTMLElement | null>(null);
  const open = Boolean(anchor);
  return (
    <Box role="group" sx={{ display: 'inline-flex', gap: '2px', flexShrink: 0 }}>
      <Button
        variant={variant}
        size={size}
        startIcon={startIcon}
        disabled={disabled}
        aria-label={ariaLabel}
        onClick={onClick}
        sx={{ borderTopRightRadius: INNER_CORNER, borderBottomRightRadius: INNER_CORNER, ...(ariaLabel && !startIcon ? { minWidth: 0, px: 1 } : {}) }}
      >
        {children}
      </Button>
      <Button
        variant={variant}
        size={size}
        disabled={disabled}
        aria-label={menuLabel}
        aria-haspopup="menu"
        aria-expanded={open}
        onClick={(e) => setAnchor(e.currentTarget)}
        // While the menu is open the trailing segment is fully round, as Material 3 shows it selected.
        sx={{ minWidth: 0, px: size === 'small' ? 0.5 : 1, ...(open ? {} : { borderTopLeftRadius: INNER_CORNER, borderBottomLeftRadius: INNER_CORNER }) }}
      >
        <ExpandMore fontSize="small" sx={{ transition: 'transform 200ms', transform: open ? 'rotate(180deg)' : 'none' }} />
      </Button>
      <Menu anchorEl={anchor} open={open} onClose={() => setAnchor(null)}>
        {menu(() => setAnchor(null))}
      </Menu>
    </Box>
  );
}
