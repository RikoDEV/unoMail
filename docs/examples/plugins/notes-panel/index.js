// Notes: a page of its own in the navigation, and a small view under each message showing
// how many notes there are. Both are views of this plug-in, drawn in their own frames.
const context = await unomail.ready;
document.documentElement.dir = context.dir;
document.documentElement.lang = context.locale;

const SIZES = { small: '13px', medium: '15px', large: '18px' };

if (context.view === 'page') {
  const style = document.createElement('style');
  style.textContent = `
    body { padding: 12px; display: flex; flex-direction: column; gap: 8px; height: 100vh; box-sizing: border-box; }
    textarea { flex: 1; resize: none; font: inherit; padding: 8px; border-radius: 8px; border: 1px solid #8888; background: transparent; color: inherit; }
    small { opacity: .7; }
  `;
  document.head.append(style);
  const area = document.createElement('textarea');
  area.setAttribute('aria-label', 'Notes');
  const status = document.createElement('small');
  document.body.append(area, status);

  const applySettings = async () => {
    const { size } = await unomail.settings.get();
    area.style.fontSize = SIZES[size] ?? SIZES.medium;
  };
  area.value = (await unomail.storage.get('text')) ?? '';
  await applySettings();
  unomail.on('settings:change', applySettings);

  let timer;
  area.addEventListener('input', () => {
    status.textContent = 'Saving…';
    clearTimeout(timer);
    timer = setTimeout(async () => {
      await unomail.storage.set('text', area.value);
      status.textContent = 'Saved';
    }, 500);
  });
} else if (context.view === 'reader') {
  document.body.style.cssText = 'margin: 0; font: 13px system-ui; opacity: .75';
  const text = (await unomail.storage.get('text')) ?? '';
  const lines = text.split('\n').filter((line) => line.trim()).length;
  document.body.textContent = lines ? `You have ${lines} note${lines === 1 ? '' : 's'}.` : 'No notes yet.';
} else {
  await unomail.ui.mount({ slot: 'app.navigation', id: 'page', title: 'Notes' });
  await unomail.ui.mount({ slot: 'reader.footer', id: 'reader', title: 'Notes', height: 32 });
  await unomail.ui.addItem({ slot: 'reader.header', id: 'open', label: 'Open notes', icon: 'note', onClick: () => unomail.ui.navigate('page') });
}
