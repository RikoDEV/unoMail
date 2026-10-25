// Cloud files: a WebDAV integration that runs entirely in the browser.
//
// - The administrator names the cloud server (a `host` setting), which lets the plug-in
//   connect to it, and its WebDAV path.
// - Each user enters their cloud user name and an app password (a secret setting).
// - "Save to cloud" under a message uploads its attachments; "Attach from cloud" in the
//   composer opens a panel listing the user's files.
//
// The cloud must allow cross-origin requests from plug-in frames (`Origin: null`) with the
// Authorization header; for Nextcloud, for example with a CORS rule in the web server.
await unomail.ready;

const encode = (path) => path.split('/').map(encodeURIComponent).join('/');

async function cloud() {
  const [admin, user] = await Promise.all([unomail.settings.getAdmin(), unomail.settings.get()]);
  if (!admin.server || !user.username || !user.password) {
    throw new Error('Set up the cloud in Settings → General → Add-ons first.');
  }
  const root = `https://${admin.server}${admin.davPath.replace('{user}', encodeURIComponent(user.username))}`;
  const authorization = `Basic ${btoa(`${user.username}:${user.password}`)}`;
  const request = async (method, path, init = {}) => {
    const response = await fetch(`${root}/${encode(path)}`, { ...init, method, headers: { Authorization: authorization, ...init.headers } });
    if (!response.ok && response.status !== 405) throw new Error(`The cloud answered ${response.status}.`);
    return response;
  };
  return { request, folder: user.folder || 'Mail attachments' };
}

// --- Saving attachments ---------------------------------------------------------------------

async function saveAttachments() {
  const files = await unomail.message.getAttachments();
  if (files.length === 0) return unomail.notify('This message has no attachments.');
  const { request, folder } = await cloud();
  await request('MKCOL', folder); // 405: it exists already
  for (const file of files) {
    const data = await unomail.message.getAttachment(file.id);
    await request('PUT', `${folder}/${file.name}`, { body: data, headers: { 'Content-Type': file.type || 'application/octet-stream' } });
  }
  await unomail.notify(`Saved ${files.length} file${files.length === 1 ? '' : 's'} to “${folder}”.`);
}

unomail.ui.addItem({
  slot: 'reader.header',
  id: 'save',
  label: 'Save to cloud',
  icon: 'cloud',
  onClick: () => saveAttachments().catch((error) => unomail.notify(error.message)),
});

// --- Attaching cloud files ------------------------------------------------------------------

/** The files in a folder, from a WebDAV PROPFIND. */
async function list(path) {
  const { request } = await cloud();
  const response = await request('PROPFIND', path, {
    headers: { Depth: '1', 'Content-Type': 'application/xml' },
    body: '<?xml version="1.0"?><d:propfind xmlns:d="DAV:"><d:prop><d:displayname/><d:getcontentlength/><d:getcontenttype/><d:resourcetype/></d:prop></d:propfind>',
  });
  const xml = new DOMParser().parseFromString(await response.text(), 'application/xml');
  return [...xml.getElementsByTagNameNS('DAV:', 'response')].slice(1).map((entry) => {
    const href = decodeURIComponent(entry.getElementsByTagNameNS('DAV:', 'href')[0].textContent);
    const name = href.replace(/\/$/, '').split('/').pop();
    return {
      name,
      path: path ? `${path}/${name}` : name,
      folder: entry.getElementsByTagNameNS('DAV:', 'collection').length > 0,
      type: entry.getElementsByTagNameNS('DAV:', 'getcontenttype')[0]?.textContent || 'application/octet-stream',
    };
  });
}

/** Draws the picker into this (the main) frame, which the panel shows. */
async function showFolder(path) {
  document.body.replaceChildren();
  document.body.style.cssText = 'margin: 0; padding: 8px; font: 14px system-ui';
  const status = document.createElement('p');
  status.textContent = 'Loading…';
  document.body.append(status);
  try {
    const entries = await list(path);
    status.remove();
    const items = path ? [{ name: '..', path: path.split('/').slice(0, -1).join('/'), folder: true }, ...entries] : entries;
    for (const entry of items) {
      const button = document.createElement('button');
      button.textContent = entry.folder ? `📁 ${entry.name}` : entry.name;
      button.style.cssText = 'display: block; width: 100%; text-align: start; padding: 8px; border: 0; background: none; color: inherit; font: inherit; cursor: pointer';
      button.onclick = () => (entry.folder ? showFolder(entry.path) : attach(entry));
      document.body.append(button);
    }
  } catch (error) {
    status.textContent = error.message;
  }
}

async function attach(entry) {
  const { request } = await cloud();
  const data = await (await request('GET', entry.path)).blob();
  await unomail.composer.addAttachment(data, { name: entry.name, type: entry.type });
  await unomail.notify(`Attached ${entry.name}.`);
  await unomail.ui.closePanel();
}

unomail.ui.addItem({
  slot: 'composer.toolbar',
  id: 'attach',
  label: 'Attach from cloud',
  icon: 'cloud',
  onClick: async () => {
    await unomail.ui.openPanel({ title: 'Attach from cloud' });
    await showFolder('');
  },
});
