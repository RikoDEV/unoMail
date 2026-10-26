/**
 * Shared props for the mobile side menus (SwipeableDrawer): a swipe from the left edge opens
 * the menu and a swipe back closes it. The discovery peek is off, so a tap on the edge does
 * not flash the menu, and off iOS the backdrop skips its transition to stay smooth. The swipe
 * area reaches well past the browser's own back-gesture strip at the edge, so a swipe started
 * a little further in opens the menu instead of going back a page.
 */
const iOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

/**
 * The swipe area lies over the left edge of every page. A tap on it (no swipe) is handed to
 * whatever it covers, so the buttons and checkboxes there keep working. This runs on touchend:
 * MUI mounts the drawer under the finger on touchstart while it waits to see if a swipe starts,
 * so the browser's own click would land on the drawer's backdrop. That click is cancelled and
 * the drawer is skipped when looking for what lies below. Until the finger has moved far enough
 * to be a swipe, the page is marked with `data-edge-tap`, which keeps that drawer's backdrop from
 * fading in.
 */
let tapStart: { x: number; y: number } | null = null;

function setEdgeTap(on: boolean) {
  document.documentElement.toggleAttribute('data-edge-tap', on);
}

function movedTooFar(touch: React.Touch) {
  return !tapStart || Math.hypot(touch.clientX - tapStart.x, touch.clientY - tapStart.y) > 10;
}

function onTouchStart(event: React.TouchEvent<HTMLElement>) {
  const touch = event.touches[0];
  tapStart = event.touches.length === 1 && touch ? { x: touch.clientX, y: touch.clientY } : null;
  setEdgeTap(tapStart !== null);
}

function onTouchMove(event: React.TouchEvent<HTMLElement>) {
  const touch = event.touches[0];
  if (!touch || movedTooFar(touch)) setEdgeTap(false);
}

function onTouchEnd(event: React.TouchEvent<HTMLElement>) {
  const touch = event.changedTouches[0];
  const tap = touch && !movedTooFar(touch);
  tapStart = null;
  setEdgeTap(false);
  if (!touch || !tap) return;
  const area = event.currentTarget;
  const below = document
    .elementsFromPoint(touch.clientX, touch.clientY)
    .find((el) => el !== area && !el.closest('.MuiDrawer-root'));
  if (!below) return;
  event.preventDefault();
  if (below instanceof HTMLElement) below.focus({ preventScroll: true });
  below.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, view: window, clientX: touch.clientX, clientY: touch.clientY }));
}

/** Spread into a SwipeableDrawer; a drawer with slotProps of its own spreads `SWIPE.slotProps` into them. */
export const SWIPE = {
  disableBackdropTransition: !iOS,
  disableDiscovery: true,
  swipeAreaWidth: 48,
  slotProps: {
    swipeArea: { onTouchStart, onTouchMove, onTouchEnd, onTouchCancel: () => setEdgeTap(false) },
    backdrop: { sx: { '[data-edge-tap] &': { opacity: '0 !important' } } },
  },
} as const;

/** The menu buttons at the left edge are lifted above the swipe area, so that they are hit directly and not through it. */
export const ABOVE_SWIPE = { position: 'relative', zIndex: (theme: { zIndex: { drawer: number } }) => theme.zIndex.drawer } as const;
