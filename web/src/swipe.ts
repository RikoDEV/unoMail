/**
 * Shared props for the mobile side menus (SwipeableDrawer): a swipe from the left edge opens
 * the menu and a swipe back closes it. iOS reserves the edge swipe for "back", so the
 * discovery peek is off there and the backdrop skips its transition to stay smooth. The swipe
 * area reaches well past the browser's own back-gesture strip at the edge, so a swipe started
 * a little further in opens the menu instead of going back a page.
 */
const iOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

export const SWIPE = { disableBackdropTransition: !iOS, disableDiscovery: iOS, swipeAreaWidth: 48 } as const;
