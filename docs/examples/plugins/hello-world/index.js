// The smallest useful plug-in: one action in the reader and a notice.
await unomail.ready;

unomail.ui.addMessageAction({
  id: 'hello',
  label: 'Say hello',
  onClick: (message) => unomail.notify(`Hello! You are reading "${message.subject}".`),
});
