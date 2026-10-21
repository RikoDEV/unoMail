/**
 * Shared props for the mobile side menus (SwipeableDrawer): a swipe from the left edge opens
 * the menu and a swipe back closes it. iOS reserves the edge swipe for "back", so the
 * discovery peek is off there and the backdrop skips its transition to stay smooth.
 */
const iOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

export const SWIPE = { disableBackdropTransition: !iOS, disableDiscovery: iOS, swipeAreaWidth: 24 } as const;
