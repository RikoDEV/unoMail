/**
 * Shared props for the mobile side menus (SwipeableDrawer): a swipe from the left edge opens
 * the menu and a swipe back closes it. iOS reserves the edge swipe for "back", so the
 * discovery peek is off there and the backdrop skips its transition to stay smooth. The swipe
 * area reaches well past the browser's own back-gesture strip at the edge, so a swipe started
 * a little further in opens the menu instead of going back a page.
 */
const iOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

/**
 * The swipe area lies over the left edge of every page. A tap on it (no swipe) is handed to
 * whatever it covers, so the buttons and checkboxes there keep working.
 */
function passTapThrough(area: HTMLElement, x: number, y: number) {
  area.style.pointerEvents = 'none';
  const below = document.elementFromPoint(x, y);
  area.style.pointerEvents = '';
  if (below instanceof HTMLElement && below !== area) {
    below.focus({ preventScroll: true });
    below.click();
  }
}

export const SWIPE = {
  disableBackdropTransition: !iOS,
  disableDiscovery: iOS,
  swipeAreaWidth: 48,
  SwipeAreaProps: { onClick: (event: React.MouseEvent<HTMLElement>) => passTapThrough(event.currentTarget, event.clientX, event.clientY) },
} as const;

/** The menu buttons at the left edge are lifted above the swipe area, so that they are hit directly and not through it. */
export const ABOVE_SWIPE = { position: 'relative', zIndex: (theme: { zIndex: { drawer: number } }) => theme.zIndex.drawer } as const;
