/**
 * Shared props for the mobile side menus (SwipeableDrawer): a swipe from the left edge opens
 * the menu and a swipe back closes it. iOS reserves the edge swipe for "back", so the
 * discovery peek is off there and the backdrop skips its transition to stay smooth. The swipe
 * area reaches well past the browser's own back-gesture strip at the edge, so a swipe started
 * a little further in opens the menu instead of going back a page.
 */
const iOS = typeof navigator !== 'undefined' && /iPad|iPhone|iPod/.test(navigator.userAgent);

export const SWIPE = { disableBackdropTransition: !iOS, disableDiscovery: iOS, swipeAreaWidth: 48 } as const;

/** The swipe area lies over the left edge of the page, so the menu buttons sitting there are lifted above it to stay tappable. */
export const ABOVE_SWIPE = { position: 'relative', zIndex: (theme: { zIndex: { drawer: number } }) => theme.zIndex.drawer } as const;
