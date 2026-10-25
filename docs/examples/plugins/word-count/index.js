// Composer actions: read what is being written and change it.
await unomail.ready;

unomail.ui.addComposerAction({
  id: 'count',
  label: 'Count words',
  onClick: async () => {
    const subject = await unomail.composer.getSubject();
    const words = subject.trim() ? subject.trim().split(/\s+/).length : 0;
    await unomail.notify(`The subject has ${words} word${words === 1 ? '' : 's'}.`);
  },
});

unomail.ui.addComposerAction({
  id: 'signoff',
  label: 'Sign off',
  onClick: async () => {
    const { signoff } = await unomail.settings.get();
    // Inserted HTML is sanitized by the composer, like anything pasted into it.
    const text = String(signoff ?? '').replace(/[&<>]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' })[c]);
    await unomail.composer.insertHtml(`<p>${text}</p>`);
  },
});
