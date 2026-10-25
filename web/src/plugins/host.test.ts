import { afterEach, describe, expect, it, vi } from 'vitest';
import { registrySnapshot, resetPlugins } from '../lib/plugins';
import { createRunning, handleCall, registerPackage, stopPlugin } from './host';

const plugin = (permissions: string[] = [], view: string | null = null, adminOnly = false) => {
  const info = { id: 'demo', commit: 'c'.repeat(40), name: 'Demo', permissions, adminOnly };
  registerPackage(info);
  return createRunning(info, view);
};

afterEach(() => {
  resetPlugins();
  stopPlugin('demo');
});

describe('sandboxed plug-in host', () => {
  it('refuses calls the manifest did not ask for', async () => {
    const reply = await handleCall(plugin(), { id: 1, method: 'message.getCurrent', args: [] });
    expect(reply?.error).toMatch(/message:read/);
    expect(await handleCall(plugin(['message:read']), { id: 2, method: 'message.getCurrent', args: [] })).toEqual({ reply: 2, result: null });
  });

  it('refuses unknown methods, including inherited object properties', async () => {
    for (const method of ['eval', 'constructor', '__proto__', 'toString']) {
      expect((await handleCall(plugin(), { id: 1, method, args: [] }))?.error).toBeTruthy();
    }
  });

  it('limits the request rate and size', async () => {
    const running = plugin(['notify']);
    const replies = await Promise.all(Array.from({ length: 60 }, (_, i) => handleCall(running, { id: i, method: 'notify', args: ['x'] })));
    expect(replies.filter((r) => r?.error).length).toBe(10);
    const big = await handleCall(plugin(['notify']), { id: 1, method: 'notify', args: ['x'.repeat(300 * 1024)] });
    expect(big?.error).toBeTruthy();
  });

  it('scopes registrations to the plug-in and accepts only web links', async () => {
    const running = plugin(['sidebar']);
    await handleCall(running, { id: 1, method: 'ui.addMessageAction', args: [{ id: 'go', label: 'Go' }] });
    expect(registrySnapshot().messageActions.map((a) => a.id)).toEqual(['demo:go']);
    const bad = await handleCall(running, { id: 2, method: 'ui.addSidebarLink', args: [{ id: 'x', label: 'X', href: 'javascript:alert(1)' }] });
    expect(bad?.error).toBeTruthy();
    expect(registrySnapshot().sidebarLinks).toEqual([]);
  });

  it('sends message content only to plug-ins allowed to read it', async () => {
    const reader = plugin(['message:read']);
    const port = { postMessage: vi.fn(), close: vi.fn() } as unknown as MessagePort;
    reader.port = port;
    await handleCall(reader, { id: 1, method: 'ui.addMessageAction', args: [{ id: 'go', label: 'Go' }] });
    registrySnapshot().messageActions[0].onClick({ id: 'm1', subject: 'Secret', from: [], to: [], receivedAt: '', html: '<p>x</p>', attachments: [] });
    expect(port.postMessage).toHaveBeenCalledWith(expect.objectContaining({ action: 'message:go', payload: expect.objectContaining({ subject: 'Secret' }) }));

    resetPlugins();
    const blind = plugin();
    blind.port = { postMessage: vi.fn(), close: vi.fn() } as unknown as MessagePort;
    await handleCall(blind, { id: 1, method: 'ui.addMessageAction', args: [{ id: 'go', label: 'Go' }] });
    registrySnapshot().messageActions[0].onClick({ id: 'm1', subject: 'Secret', from: [], to: [], receivedAt: '', html: '', attachments: [] });
    expect(blind.port.postMessage).toHaveBeenCalledWith({ action: 'message:go', payload: { id: 'm1' } });
  });

  it('places items and views only where the permissions allow', async () => {
    const running = plugin(['ui:widget']);
    expect((await handleCall(running, { id: 1, method: 'ui.addItem', args: [{ slot: 'reader.footer', id: 'go', label: 'Go', icon: 'star' }] }))?.error).toBeUndefined();
    expect((await handleCall(running, { id: 2, method: 'ui.addItem', args: [{ slot: 'nowhere', id: 'x', label: 'X' }] }))?.error).toBeTruthy();
    expect((await handleCall(running, { id: 3, method: 'ui.mount', args: [{ slot: 'reader.footer', id: 'card', height: 9999 }] }))?.error).toBeUndefined();
    expect((await handleCall(running, { id: 4, method: 'ui.mount', args: [{ slot: 'admin.section', id: 'admin' }] }))?.error).toMatch(/ui:admin/);
    const registry = registrySnapshot();
    expect(registry.items.map((i) => i.id)).toEqual(['demo:go']);
    expect(registry.mounts).toEqual([expect.objectContaining({ id: 'card', slot: 'reader.footer', height: 1200 })]);
  });

  it('lets only listed features be hidden, with ui:replace', async () => {
    expect((await handleCall(plugin(), { id: 1, method: 'features.hide', args: ['calendar'] }))?.error).toMatch(/ui:replace/);
    const running = plugin(['ui:replace']);
    for (const protectedFeature of ['signin', 'unsafe-content', 'addons', '__proto__']) {
      expect((await handleCall(running, { id: 2, method: 'features.hide', args: [protectedFeature] }))?.error).toBeTruthy();
    }
    await handleCall(running, { id: 3, method: 'features.hide', args: ['calendar'] });
    expect(registrySnapshot().hidden.calendar).toEqual(['demo']);
    stopPlugin('demo');
    expect(registrySnapshot().hidden.calendar).toEqual([]);
  });

  it('keeps views and admin-only frames from changing the interface', async () => {
    expect((await handleCall(plugin([], 'card'), { id: 1, method: 'ui.addMessageAction', args: [{ id: 'go', label: 'Go' }] }))?.error).toBeTruthy();
    const admin = plugin(['ui:admin'], null, true);
    expect((await handleCall(admin, { id: 2, method: 'ui.addMessageAction', args: [{ id: 'go', label: 'Go' }] }))?.error).toBeTruthy();
    expect((await handleCall(admin, { id: 3, method: 'ui.mount', args: [{ slot: 'admin.section', id: 'stats' }] }))?.error).toBeUndefined();
  });

  it("confines server calls to the plug-in's own routes", async () => {
    const running = plugin(['server:routes']);
    for (const path of ['../../me', 'a/../../b', 'x?y=1']) {
      expect((await handleCall(running, { id: 1, method: 'server.call', args: [path, {}] }))?.error).toBeTruthy();
    }
  });

  it('hands out attachments as files, never their addresses', async () => {
    const reader = plugin(['attachments:read']);
    reader.port = { postMessage: vi.fn(), close: vi.fn() } as unknown as MessagePort;
    await handleCall(reader, { id: 1, method: 'ui.addMessageAction', args: [{ id: 'save', label: 'Save' }] });
    const message = { id: 'm1', subject: 'S', from: [], to: [], receivedAt: '', html: '', attachments: [{ id: 'b1', name: 'a.txt', type: 'text/plain', size: 5, url: '/jmap/download/a/b1/a.txt' }] };
    registrySnapshot().messageActions[0].onClick(message);
    expect(reader.port.postMessage).toHaveBeenCalledWith({ action: 'message:save', payload: { id: 'm1', attachments: [{ id: 'b1', name: 'a.txt', type: 'text/plain', size: 5 }] } });
    const fetched = vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('hello', { status: 200 }));
    const reply = await handleCall(reader, { id: 2, method: 'message.getAttachment', args: ['b1'] });
    expect(fetched).toHaveBeenCalledWith('/jmap/download/a/b1/a.txt', { credentials: 'same-origin' });
    expect(reply?.result).toBeInstanceOf(File);
    expect((reply?.result as File).name).toBe('a.txt');
    expect((await handleCall(reader, { id: 3, method: 'message.getAttachment', args: ['other'] }))?.error).toBeTruthy();
    fetched.mockRestore();
  });

  it('attaches files and links to the open composer', async () => {
    const { composerOpened } = await import('./host');
    const added: File[] = [];
    const inserted: string[] = [];
    composerOpened({ getSubject: () => '', setSubject: () => {}, getRecipients: () => '', insertHtml: (html) => inserted.push(html), addFiles: async (files) => void added.push(...files) });
    const writer = plugin(['composer:write']);
    await handleCall(writer, { id: 1, method: 'composer.addAttachment', args: [{ file: new Blob(['x']), name: '../report.pdf', type: 'application/pdf' }] });
    expect(added.map((f) => [f.name, f.type])).toEqual([['.._report.pdf', 'application/pdf']]);
    expect((await handleCall(writer, { id: 2, method: 'composer.addAttachment', args: [{ file: 'not a file' }] }))?.error).toBeTruthy();
    await handleCall(writer, { id: 3, method: 'composer.insertLink', args: [{ href: 'https://files.example/s/1?a=1&b=2', text: '<b>Report</b>' }] });
    expect(inserted).toEqual(['<a href="https://files.example/s/1?a=1&amp;b=2">&lt;b&gt;Report&lt;/b&gt;</a>']);
    expect((await handleCall(writer, { id: 4, method: 'composer.insertLink', args: [{ href: 'javascript:alert(1)' }] }))?.error).toBeTruthy();
  });

  it('asks before signing in, only to declared hosts and with a state', async () => {
    const { useAuthRequest: _unused, answerAuth } = await import('./host');
    void _unused;
    const signer = plugin(['auth', 'network:login.example.com']);
    expect((await handleCall(signer, { id: 1, method: 'auth.start', args: [{ url: 'https://evil.example/authorize?state=0123456789abcdef' }] }))?.error).toMatch(/network:evil.example/);
    expect((await handleCall(signer, { id: 2, method: 'auth.start', args: [{ url: 'https://login.example.com/authorize?state=short' }] }))?.error).toMatch(/state/);
    const pending = handleCall(signer, { id: 3, method: 'auth.start', args: [{ url: 'https://login.example.com/authorize?state=0123456789abcdef' }] });
    await Promise.resolve();
    answerAuth(false);
    expect((await pending)?.error).toMatch(/cancelled/);
  });
});
