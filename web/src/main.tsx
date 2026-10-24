import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { loadInterfaceLanguage } from './i18n';

// The service worker (public/sw.js) makes the web mail installable and keeps its shell for offline starts.
if (import.meta.env.PROD && 'serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js', { scope: '/' }).catch(() => {});
}

// The language comes first: the app's modules translate some texts as they load.
await loadInterfaceLanguage();
const { App } = await import('./app');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
