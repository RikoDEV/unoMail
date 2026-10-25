// The web part of the subject tagger: a page in the administration that asks the plug-in's
// own server route which prefix is in use.
const context = await unomail.ready;

if (context.view === 'admin') {
  document.documentElement.dir = context.dir;
  const { prefix } = await unomail.server.call('info');
  const page = document.createElement('main');
  page.style.cssText = 'padding: 16px; line-height: 1.5';
  const heading = document.createElement('h2');
  heading.textContent = 'Subject tagger';
  const text = document.createElement('p');
  text.textContent = `Incoming mail gets the header X-Tagged-By and the prefix "${prefix}" in front of its subject. Change the prefix in Integrations → Plug-ins and themes → Settings.`;
  page.append(heading, text);
  document.body.append(page);
} else {
  unomail.ui.mount({ slot: 'admin.section', id: 'admin', title: 'Subject tagger' });
}
