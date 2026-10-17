import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { loadInterfaceLanguage } from './i18n';

// The language comes first: the app's modules translate some texts as they load.
await loadInterfaceLanguage();
const { App } = await import('./app');

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
