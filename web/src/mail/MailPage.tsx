import { LinearProgress } from '../ui/progress';
import Edit from '@mui/icons-material/Edit';
import MenuIcon from '@mui/icons-material/Menu';
import Search from '@mui/icons-material/Search';
import Tune from '@mui/icons-material/Tune';
import {
  Alert, Box, Button, CircularProgress, Dialog, DialogContent, DialogTitle, SwipeableDrawer, Fab, IconButton, InputBase, List,
  Menu, MenuItem, Paper, Snackbar, TextField, Tooltip, Typography, useMediaQuery, useTheme,
} from '@mui/material';
import { ABOVE_SWIPE, SWIPE } from '../lib/swipe';
import { Subscriptions } from './Subscriptions';
import { useVirtualizer } from '@tanstack/react-virtual';
import { type ReactElement, useCallback, useEffect, useMemo, useRef, useState } from 'react';
import { Link as RouterLink, useNavigate, useParams, useSearchParams } from 'react-router-dom';
import { del, post, errorText } from '../lib/api';
import { useAuth } from '../app';
import { setPluginNotifier, usePlugins } from '../lib/plugins';
import { usePrefs } from '../lib/prefs';
import { TopBar, useTitle } from '../ui/shell';
import { cachedList, cachedMailboxes, cachedThread, cacheList, cacheMailboxes, cacheThread, openCache } from './cache';
import { Composer, type SentInfo } from './Composer';
import { CATEGORIES, type CategoryLatest, type CategoryName, categoryCounts, categoryLatest, exportUrl, importMessages, type LabelDetail, listLabelDetails, saveLabel } from './extra';
import { flushOutbox, openOutbox, pendingCount, performOrQueue, queuedPendingFiles } from './outbox';
import { sweepPendingFiles } from './pendingFiles';
import {
  folderName,
  accountId as fetchAccountId, cancelSubmission, createMailbox, destroyMailbox, type Draft, type EmailFull, type EmailSummary, getThread,
  listMailboxes, listScheduled, type Mailbox, normalizeLabel, queryAllIds, queryEmails, resetSession, setCategory, setKeyword, snooze,
} from './jmapClient';
import { Reader } from './Reader';
import { ShareDialog } from './ShareDialog';
import { AdvancedSearch } from './AdvancedSearch';
import { type BulkAction, ListToolbar } from './ListToolbar';
import { LabelDialog } from './LabelDialog';
import { CategoryTabs } from './CategoryTabs';
import { type LabelDialogState, MailSidebar } from './MailSidebar';
import { EmailRow, type RowHandlers } from './EmailRow';
import { RowMenu, type RowMenuPick, type RowMenuTarget } from './RowMenu';
import { AttachmentPreview, type PreviewFile } from './Preview';
import { parseMailto } from './mailto';
import { pageNotifier } from './notifications';
import { draftFor, EMPTY_DRAFT } from './replyDraft';

import { parseQuery, withScope } from './searchQuery';

import { t, uiLocale } from '../i18n';
import { readLocal, writeLocal } from '../lib/storage';
import { DialogButtons } from '../admin/common';
const PAGE_SIZE = 50;

/** A label name from the address bar; a broken encoding is shown as typed rather than crashing the page. */
function decodeLabel(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

export default function MailPage() {
  const { account } = useAuth();
  const navigate = useNavigate();
  const params = useParams();
  const [mailboxSlug, threadId] = (params['*'] ?? '').split('/');

  const [accountId, setAccountId] = useState('');
  const [mailboxes, setMailboxes] = useState<Mailbox[]>([]);
  const [emails, setEmails] = useState<EmailSummary[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(false);
  const [search, setSearch] = useState('');
  const [serverSearch, setServerSearch] = useState('');
  const [cursor, setCursor] = useState(0);
  const [thread, setThread] = useState<EmailFull[] | null>(null);
  const [draft, setDraft] = useState<{ key: number; draft: Draft; emailId?: string } | null>(null);
  const [notice, setNotice] = useState('');
  // A message just sent that can still be called back.
  const [undoable, setUndoable] = useState<SentInfo | null>(null);
  const [scheduledCount, setScheduledCount] = useState(0);
  useEffect(() => {
    if (accountId) void listScheduled().then((list) => setScheduledCount(list.length), () => {});
  }, [accountId, emails]);
  // The sidebar is either full or reduced to a strip of icons; the choice is remembered.
  const [sidebar, setSidebar] = useState(() => readLocal('unomail.sidebar') !== 'mini');
  useEffect(() => void writeLocal('unomail.sidebar', sidebar ? 'full' : 'mini'), [sidebar]);
  // On small screens the folders slide in over the page instead, and the list gets the width.
  const theme = useTheme();
  const compact = useMediaQuery(theme.breakpoints.down('md'));
  const phone = useMediaQuery(theme.breakpoints.down('sm'));
  const [drawerOpen, setDrawerOpen] = useState(false);
  useEffect(() => setDrawerOpen(false), [params['*'], compact]);
  const mini = !sidebar && !compact;
  /** Sidebar entries are real links, so they can be middle-clicked into a new tab. */
  const linkTo = (to: string) => ({ component: RouterLink, to, onClick: () => setSearch('') });
  const [newFolder, setNewFolder] = useState<string | null>(null);
  const [labels, setLabels] = useState<string[]>([]);
  const [labelDetails, setLabelDetails] = useState<LabelDetail[]>([]);
  const [labelDialog, setLabelDialog] = useState<LabelDialogState | null>(null);
  const prefs = usePrefs();
  // Inbox categories (General, Offers, ...) and their unread counts.
  const [category, setCategoryTab] = useState<CategoryName>('general');
  const [counts, setCounts] = useState<Partial<Record<CategoryName, number>>>({});
  const [latest, setLatest] = useState<Partial<Record<CategoryName, CategoryLatest>>>({});
  const refreshCategories = useCallback(() => {
    void categoryCounts().then(setCounts).catch(() => {});
    void categoryLatest().then(setLatest).catch(() => {});
  }, []);
  // Selection in the list: ids of the listed conversations, or everything in the folder.
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [allInFolder, setAllInFolder] = useState(false);
  const [rowMenu, setRowMenu] = useState<RowMenuTarget | null>(null);
  const [threadVersion, setThreadVersion] = useState(0);
  const [offline, setOffline] = useState(false);
  const [pending, setPending] = useState(0);
  const searchInput = useRef<HTMLInputElement>(null);
  const requestSeq = useRef(0);
  const plugins = usePlugins();
  const [searchParams, setSearchParams] = useSearchParams();
  // Drag and drop: the conversation being dragged and the folder or label under the pointer.
  const dragged = useRef<EmailSummary | null>(null);
  const [dropTarget, setDropTarget] = useState<string | null>(null);
  const [folderMenu, setFolderMenu] = useState<{ anchor: HTMLElement; mailbox: Mailbox } | null>(null);
  const [sharing, setSharing] = useState<Mailbox | null>(null);
  const importInput = useRef<HTMLInputElement>(null);
  const importTarget = useRef<Mailbox | null>(null);

  const mailbox = useMemo(() => mailboxes.find((m) => m.id === mailboxSlug) ?? mailboxes.find((m) => m.role === (mailboxSlug || 'inbox')), [mailboxes, mailboxSlug]);
  // "label:<name>" in the URL shows every conversation carrying that label.
  const label = mailboxSlug?.startsWith('label:') ? decodeLabel(mailboxSlug.slice(6)) : null;
  // "all" is the virtual All mail folder: every message except those in Trash and Junk.
  const allMail = mailboxSlug === 'all' && !mailbox;
  // "subscriptions" is the Manage subscriptions page, shown in place of the message list.
  const subscriptionsPage = mailboxSlug === 'subscriptions' && !mailbox;
  const otherThan = useMemo(
    () => (allMail ? ['trash', 'junk'].map((role) => mailboxes.find((m) => m.role === role)?.id).filter((id): id is string => Boolean(id)) : undefined),
    [allMail, mailboxes],
  );
  const unreadInbox = mailboxes.find((m) => m.role === 'inbox')?.unreadEmails ?? 0;
  useTitle(
    thread ? thread[0]?.subject || t('(no subject)') : null,
    serverSearch ? t('Results for "{{serverSearch}}"', { serverSearch }) : label ? t('Label: {{label}}', { label }) : allMail ? t('All mail') : subscriptionsPage ? t('Subscriptions') : mailbox && folderName(mailbox),
    unreadInbox > 0 && t('{{count}} unread', { count: unreadInbox }),
  );
  const slug = label ? `label:${encodeURIComponent(label)}` : allMail ? 'all' : (mailbox?.id ?? 'inbox');
  const byRole = useCallback((role: string) => mailboxes.find((m) => m.role === role), [mailboxes]);

  const [searchPanel, setSearchPanel] = useState<HTMLElement | null>(null);
  const [preview, setPreview] = useState<PreviewFile | null>(null);
  const searchBox = useRef<HTMLFormElement>(null);
  // The search as a JMAP filter, confined to the folders it covers: all but Trash and Junk
  // unless it names others ("in:anywhere", "in:sent", "in:<folder>").
  const searchFilter = useMemo(() => {
    if (!serverSearch) return undefined;
    const parsed = parseQuery(serverSearch);
    const excluded = ['trash', 'junk'].map((role) => mailboxes.find((m) => m.role === role)?.id).filter((id): id is string => Boolean(id));
    let folders: Record<string, unknown> | null = null;
    if (parsed.scope.kind === 'default') folders = excluded.length ? { inMailboxOtherThan: excluded } : null;
    else if (parsed.scope.kind === 'folder') {
      const wanted = parsed.scope.name.toLowerCase();
      const role = { spam: 'junk', bin: 'trash', deleted: 'trash', all: '' }[wanted] ?? wanted;
      const found = mailboxes.find((m) => m.role === role) ?? mailboxes.find((m) => m.name.toLowerCase() === wanted || (m.name === 'INBOX' && wanted === 'inbox'));
      // No such folder: nothing is found, rather than everything.
      folders = found ? { inMailbox: found.id } : { operator: 'OR', conditions: [] };
    }
    return withScope(parsed.filter, folders);
  }, [serverSearch, mailboxes]);
  const density = prefs.density ?? 'condensed';

  // Instant client-side filtering of what is already loaded, while the server search runs.
  const visible = useMemo(() => {
    const needle = search.trim().toLowerCase();
    // Operators are for the server; only plain words are matched here meanwhile.
    if (!needle || needle === serverSearch.toLowerCase() || parseQuery(needle).operators) return emails;
    return emails.filter((e) => [e.subject, e.preview, ...(e.from ?? []).flatMap((a) => [a.name ?? '', a.email])].some((field) => field.toLowerCase().includes(needle)));
  }, [emails, search, serverSearch]);

  const refreshMailboxes = useCallback(
    () =>
      listMailboxes()
        .then((list) => {
          setMailboxes(list);
          cacheMailboxes(list);
        })
        .catch(() => {}),
    [],
  );
  const refreshLabels = useCallback(
    () =>
      listLabelDetails()
        .then((details) => {
          setLabelDetails(details);
          setLabels(details.map((detail) => detail.name));
        })
        .catch(() => {}),
    [],
  );
  const labelColor = useCallback((name: string) => labelDetails.find((detail) => detail.name === name)?.color ?? '', [labelDetails]);
  // The inbox is split into category tabs unless the user switched that off.
  const categorised = mailbox?.role === 'inbox' && !label && prefs.categories !== false;
  const activeCategory = categorised && !serverSearch ? category : undefined;

  const load = useCallback(
    async (position: number) => {
      if (!mailbox && !label && !allMail) return;
      const seq = ++requestSeq.current;
      const cacheKey = position === 0 && !serverSearch ? (label ? `label:${label}` : allMail ? 'all' : activeCategory ? `${mailbox!.id}:${activeCategory}` : mailbox!.id) : null;
      // Show the saved copy at once; the network result replaces it when it arrives.
      const saved = cacheKey ? cachedList<EmailSummary[]>(cacheKey) : undefined;
      if (saved) {
        setEmails(saved.emails);
        setTotal(saved.total);
      }
      setLoading(true);
      try {
        const result = await queryEmails({ mailboxId: mailbox?.id, otherThan, label: label ?? undefined, search: searchFilter, category: activeCategory, position, limit: PAGE_SIZE });
        if (categorised) refreshCategories();
        // A slower, older response must not overwrite a newer one.
        if (seq !== requestSeq.current) return;
        setOffline(false);
        // Back online: replay what was done without a connection.
        if (pendingCount() > 0) {
          const flushed = await flushOutbox();
          setPending(flushed.remaining);
          if (flushed.rejected.length > 0) setNotice(t('A change made offline was refused: {{value}}', { value: flushed.rejected[0] }));
          else if (flushed.done > 0) setNotice(t('{{count}} offline changes synchronised', { count: flushed.done }));
        }
        if (cacheKey) cacheList(cacheKey, result.emails, result.total);
        setTotal(result.total);
        setEmails((current) => (position === 0 ? result.emails : [...current, ...result.emails.filter((e) => !current.some((c) => c.id === e.id))]));
      } catch (err) {
        if (seq !== requestSeq.current) return;
        // Network failure: keep working from the saved copy.
        if (err instanceof TypeError) setOffline(true);
        else setNotice(errorText(err, t('Could not load messages')));
      } finally {
        if (seq === requestSeq.current) setLoading(false);
      }
    },
    [mailbox?.id, allMail, otherThan, label, serverSearch, searchFilter, activeCategory, categorised, refreshCategories],
  );

  useEffect(() => {
    resetSession();
    if (account) {
      openCache(account.email);
      openOutbox(account.email);
      setPending(pendingCount());
      // Files left behind by a tab that was closed mid-composition.
      void sweepPendingFiles(queuedPendingFiles());
      const saved = cachedMailboxes<Mailbox[]>();
      if (saved) setMailboxes(saved);
    }
    fetchAccountId().then(setAccountId).catch(() => {});
    void refreshMailboxes();
    void refreshLabels();
  }, [refreshMailboxes, refreshLabels, account]);

  useEffect(() => {
    setCursor(0);
    void load(0);
  }, [load]);

  // The browser reports the connection coming back: synchronise right away.
  useEffect(() => {
    const onOnline = () => void load(0);
    window.addEventListener('online', onOnline);
    return () => window.removeEventListener('online', onOnline);
  }, [load]);

  // Debounce the server-side search.
  useEffect(() => {
    const timer = setTimeout(() => setServerSearch(search.trim()), 300);
    return () => clearTimeout(timer);
  }, [search]);

  useEffect(() => {
    if (!threadId) {
      setThread(null);
      return;
    }
    let cancelled = false;
    const savedThread = cachedThread<EmailFull[]>(threadId);
    setThread(savedThread ?? null);
    getThread(threadId)
      .then((list) => {
        if (cancelled) return;
        setThread(list);
        cacheThread(threadId, list);
        const unread = list.filter((e) => !e.keywords.$seen).map((e) => e.id);
        if (unread.length) {
          setEmails((current) => current.map((e) => (e.threadId === threadId ? { ...e, keywords: { ...e.keywords, $seen: true } } : e)));
          void setKeyword(unread, '$seen', true).then(refreshMailboxes);
        }
      })
      .catch(() => !cancelled && !savedThread && setNotice(t('Could not open the conversation')));
    return () => {
      cancelled = true;
    };
  }, [threadId, refreshMailboxes, threadVersion]);

  // A different folder, category or search starts with nothing selected.
  useEffect(() => {
    setSelected(new Set());
    setAllInFolder(false);
  }, [mailbox?.id, allMail, label, serverSearch, activeCategory]);

  // Tools inside the reader (block sender, move to category) ask for a reload this way.
  useEffect(() => {
    const onRefresh = () => {
      void load(0);
      setThreadVersion((version) => version + 1);
    };
    window.addEventListener('unomail:refresh', onRefresh);
    return () => window.removeEventListener('unomail:refresh', onRefresh);
  }, [load]);

  // Without Web Push, this tab announces new mail while it is in the background.
  const ownEmail = account?.email ?? '';
  const notifyNewMail = useMemo(() => pageNotifier(ownEmail, (thread) => navigate(`/mail/inbox/${thread}`)), [ownEmail, navigate]);

  // Push: the server announces changes; refresh folder counts and the first page. One stream
  // for the life of the page: reopening it whenever the folder or the open conversation
  // changes would lose what the server announced in between. The handlers it calls are the
  // current ones, through a ref.
  const onPush = useRef<() => void>(() => {});
  onPush.current = () => {
    void refreshMailboxes();
    void load(0);
    notifyNewMail();
  };
  useEffect(() => {
    const source = new EventSource('/jmap/eventsource');
    let timer: ReturnType<typeof setTimeout> | undefined;
    let connected = false;
    const refresh = () => {
      clearTimeout(timer);
      timer = setTimeout(() => onPush.current(), 400);
    };
    source.addEventListener('state', refresh);
    // After a reconnect (the browser retries a dropped stream), catch up on what was missed.
    source.addEventListener('open', () => {
      if (connected) refresh();
      connected = true;
    });
    return () => {
      clearTimeout(timer);
      source.close();
    };
  }, []);

  // A click on a push notification (public/sw.js) while unoMail is open shows that conversation here.
  useEffect(() => {
    if (!('serviceWorker' in navigator)) return;
    const onMessage = (event: MessageEvent) => {
      const url = event.data?.type === 'open' ? String(event.data.url ?? '') : '';
      if (url.startsWith('/mail/')) navigate(url);
    };
    navigator.serviceWorker.addEventListener('message', onMessage);
    return () => navigator.serviceWorker.removeEventListener('message', onMessage);
  }, [navigate]);

  const open = useCallback((email: EmailSummary) => navigate(`/mail/${slug}/${email.threadId}`), [navigate, slug]);
  const closeThread = useCallback(() => navigate(`/mail/${slug}`), [navigate, slug]);

  /** Applies an action to a whole conversation, updating the list optimistically. */
  const act = useCallback(
    async (target: EmailSummary | undefined, action: 'archive' | 'trash' | 'junk' | 'inbox' | 'unread' | 'read' | 'star') => {
      if (!target) return;
      const ids = thread && thread[0]?.threadId === target.threadId ? thread.map((e) => e.id) : [target.id];
      const remove = () => setEmails((current) => current.filter((e) => e.threadId !== target.threadId));
      const queued = () => {
        setOffline(true);
        setPending(pendingCount());
        setNotice(t('Saved on this device; it will be synchronised when you are back online'));
      };
      try {
        if (action === 'star') {
          const starred = !target.keywords.$flagged;
          setEmails((current) => current.map((e) => (e.id === target.id ? { ...e, keywords: { ...e.keywords, $flagged: starred } } : e)));
          if (await performOrQueue({ type: 'keyword', ids: [target.id], keyword: '$flagged', value: starred })) queued();
          return;
        }
        if (action === 'unread' || action === 'read') {
          const seen = action === 'read';
          setEmails((current) => current.map((e) => (e.threadId === target.threadId ? { ...e, keywords: { ...e.keywords, $seen: seen } } : e)));
          if (await performOrQueue({ type: 'keyword', ids, keyword: '$seen', value: seen })) queued();
          // An open conversation would be marked as read again at once.
          if (!seen && threadId === target.threadId) closeThread();
        } else {
          const destination = byRole(action);
          if (!destination) return;
          remove();
          if (threadId === target.threadId) closeThread();
          // Deleting from the trash removes the conversation for good.
          const wasQueued =
            action === 'trash' && mailbox?.role === 'trash' ? await performOrQueue({ type: 'destroy', ids }) : await performOrQueue({ type: 'move', ids, mailboxId: destination.id });
          if (wasQueued) queued();
          else setNotice(action === 'archive' ? t('Conversation archived') : action === 'junk' ? t('Reported as spam') : action === 'inbox' ? t('Marked as not spam and moved to the inbox') : t('Conversation deleted'));
        }
        void refreshMailboxes();
      } catch (err) {
        setNotice(errorText(err, t('The action failed')));
        void load(0);
      }
    },
    [thread, byRole, threadId, closeThread, mailbox?.role, refreshMailboxes, load],
  );

  /** Adds or removes a label on every message of the open conversation. */
  const toggleLabel = useCallback(
    async (name: string, on: boolean) => {
      if (!thread) return;
      const ids = thread.map((e) => e.id);
      const apply = <T extends { id: string; keywords: Record<string, boolean> }>(e: T): T => (ids.includes(e.id) ? { ...e, keywords: { ...e.keywords, [name]: on } } : e);
      setThread((current) => current && current.map(apply));
      setEmails((current) => current.map(apply));
      try {
        if (await performOrQueue({ type: 'keyword', ids, keyword: name, value: on })) {
          setOffline(true);
          setPending(pendingCount());
        }
        await refreshLabels();
      } catch (err) {
        setNotice(errorText(err, t('Could not change the label')));
      }
    },
    [thread, refreshLabels],
  );

  const compose = useCallback((initial: Draft = EMPTY_DRAFT) => setDraft({ key: Date.now(), draft: initial }), []);

  // Plug-ins report to the user through the page's own notice bar.
  useEffect(() => {
    setPluginNotifier(setNotice);
    return () => setPluginNotifier(() => {});
  }, []);

  // "/mail/inbox?compose=address" opens a new message, e.g. from the address book, and
  // "?mailto=<url>" one described by a mailto: link (unoMail as the browser's mail handler).
  useEffect(() => {
    const recipient = searchParams.get('compose');
    const link = searchParams.get('mailto');
    if (recipient === null && link === null) return;
    const fromLink = link === null ? null : parseMailto(link);
    if (recipient !== null) compose({ ...EMPTY_DRAFT, to: recipient });
    else if (fromLink) compose({ ...EMPTY_DRAFT, ...fromLink });
    setSearchParams({}, { replace: true });
  }, [searchParams, setSearchParams, compose]);

  // mailto: links clicked in a message.
  useEffect(() => {
    const onMailto = (event: Event) => {
      const draft = parseMailto(String((event as CustomEvent<string>).detail ?? ''));
      if (draft) compose({ ...EMPTY_DRAFT, ...draft });
    };
    window.addEventListener('unomail:mailto', onMailto);
    return () => window.removeEventListener('unomail:mailto', onMailto);
  }, [compose]);

  /** Every message of a conversation that lives in the folder it is listed in. */
  const conversationIds = useCallback(async (email: EmailSummary): Promise<string[]> => {
    const source = Object.keys(email.mailboxIds)[0];
    try {
      const members = (await getThread(email.threadId)).filter((e) => e.mailboxIds[source]).map((e) => e.id);
      return members.length > 0 ? members : [email.id];
    } catch {
      // Offline: act on the message that is listed.
      return [email.id];
    }
  }, []);

  /** Message ids covered by the current selection. */
  async function selectionIds(all = allInFolder): Promise<string[]> {
    if (all) return queryAllIds({ mailboxId: mailbox?.id, otherThan, label: label ?? undefined, search: searchFilter, category: activeCategory });
    const groups = await Promise.all(emails.filter((email) => selected.has(email.id)).map(conversationIds));
    return [...new Set(groups.flat())];
  }

  /** Applies one action to everything that is selected. */
  async function bulk(action: BulkAction, argument?: string, all = allInFolder) {
    const count = all ? total : selected.size;
    try {
      const ids = await selectionIds(all);
      if (ids.length === 0) return;
      let wasQueued = false;
      if (action === 'read' || action === 'unread') {
        wasQueued = await performOrQueue({ type: 'keyword', ids, keyword: '$seen', value: action === 'read' });
      } else if (action === 'label') {
        wasQueued = await performOrQueue({ type: 'keyword', ids, keyword: argument!, value: true });
      } else {
        const destination = action === 'move' ? argument : byRole(action)?.id;
        if (!destination) return;
        // Deleting from the trash removes the conversations for good.
        wasQueued = action === 'trash' && mailbox?.role === 'trash' ? await performOrQueue({ type: 'destroy', ids }) : await performOrQueue({ type: 'move', ids, mailboxId: destination });
      }
      if (wasQueued) {
        setOffline(true);
        setPending(pendingCount());
      }
      const done = {
        archive: () => t('{{count}} conversations archived', { count }),
        trash: () => t('{{count}} conversations deleted', { count }),
        junk: () => t('{{count}} conversations reported as spam', { count }),
        inbox: () => t('{{count}} conversations marked as not spam', { count }),
        read: () => t('{{count}} conversations marked as read', { count }),
        unread: () => t('{{count}} conversations marked as unread', { count }),
        move: () => t('{{count}} conversations moved', { count }),
        label: () => t('{{count}} conversations labelled “{{label}}”', { count, label: argument }),
      }[action];
      setNotice(done());
      setSelected(new Set());
      setAllInFolder(false);
      void refreshMailboxes();
      void refreshLabels();
      await load(0);
    } catch (err) {
      setNotice(errorText(err, t('The action failed')));
      void load(0);
    }
  }

  function toggleSelected(id: string) {
    setAllInFolder(false);
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  /** Drops the dragged conversation on a folder (move), a label (apply) or a category tab. */
  const dropOn = useCallback(
    async (target: { mailbox?: Mailbox; label?: string; category?: CategoryName }, chosen?: EmailSummary) => {
      const email = chosen ?? dragged.current;
      dragged.current = null;
      setDropTarget(null);
      if (!email) return;
      try {
        if (target.label) {
          const name = target.label;
          setEmails((current) => current.map((e) => (e.id === email.id ? { ...e, keywords: { ...e.keywords, [name]: true } } : e)));
          if (await performOrQueue({ type: 'keyword', ids: [email.id], keyword: name, value: true })) {
            setOffline(true);
            setPending(pendingCount());
          }
          setNotice(t('Labelled “{{name}}”', { name }));
          return;
        }
        if (target.category) {
          const moved = target.category;
          await setCategory(await conversationIds(email), moved);
          setEmails((current) => current.filter((e) => e.threadId !== email.threadId));
          setNotice(t('Moved to {{label}}. New mail from this sender will go there too.', { label: CATEGORIES.find((c) => c.id === moved)?.label }));
          refreshCategories();
          return;
        }
        const destination = target.mailbox;
        if (!destination || email.mailboxIds[destination.id]) return;
        // The whole conversation moves, as far as it lives in the folder it was dragged from.
        const source = Object.keys(email.mailboxIds)[0];
        let ids = [email.id];
        try {
          const members = (await getThread(email.threadId)).filter((e) => e.mailboxIds[source]).map((e) => e.id);
          if (members.length > 0) ids = members;
        } catch {
          // Offline: move the message that is listed.
        }
        setEmails((current) => current.filter((e) => e.threadId !== email.threadId));
        if (threadId === email.threadId) navigate(`/mail/${slug}`);
        const wasQueued = await performOrQueue({ type: 'move', ids, mailboxId: destination.id });
        if (wasQueued) {
          setOffline(true);
          setPending(pendingCount());
        }
        setNotice(t('Moved to {{value}}', { value: folderName(destination) }));
        void refreshMailboxes();
      } catch (err) {
        setNotice(errorText(err, t('The message could not be moved')));
        void load(0);
      }
    },
    [threadId, navigate, slug, refreshMailboxes, load, conversationIds],
  );

  async function importInto(file: File | undefined) {
    const target = importTarget.current;
    if (!file || !target) return;
    try {
      const result = await importMessages(target.id, file);
      setNotice(t('{{count}} messages imported', { count: result.imported }) + (result.skipped ? t(', {{count}} skipped', { count: result.skipped }) : ''));
      await refreshMailboxes();
      void load(0);
    } catch (err) {
      setNotice(errorText(err, t('The file could not be imported')));
    }
  }

  /** Props that make a sidebar entry accept a dragged conversation. */
  const dropProps = (key: string, target: { mailbox?: Mailbox; label?: string; category?: CategoryName }) => ({
    onDragOver: (event: React.DragEvent) => {
      if (!dragged.current) return;
      event.preventDefault();
      event.dataTransfer.dropEffect = 'move';
      if (dropTarget !== key) setDropTarget(key);
    },
    onDragLeave: () => setDropTarget((current) => (current === key ? null : current)),
    onDrop: (event: React.DragEvent) => {
      event.preventDefault();
      void dropOn(target);
    },
  });
  const dropStyle = (key: string) => (dropTarget === key ? { outline: 2, outlineColor: 'primary.main', outlineStyle: 'dashed', bgcolor: 'action.hover' } : {});
  const ownMailboxes = mailboxes.filter((m) => !m.shareOwner);
  const sharedMailboxes = mailboxes.filter((m) => m.shareOwner);
  const current = threadId ? emails.find((e) => e.threadId === threadId) : visible[cursor];

  // Keyboard shortcuts (Gmail style). Ignored while typing.
  useEffect(() => {
    function onKey(event: KeyboardEvent) {
      const target = event.target as HTMLElement;
      if (event.ctrlKey || event.metaKey || event.altKey) return;
      // Keys pressed inside an open menu, list box or dialog belong to that widget.
      if (target.closest?.('[role="menu"], [role="listbox"], [role="dialog"]') || document.querySelector('.MuiPopover-root, .MuiDialog-root')) return;
      if (target.isContentEditable || ['INPUT', 'TEXTAREA', 'SELECT'].includes(target.tagName)) {
        if (event.key === 'Escape') target.blur();
        return;
      }
      const last = thread?.[thread.length - 1];
      switch (event.key) {
        case 'j':
          setCursor((c) => Math.min(c + 1, Math.max(visible.length - 1, 0)));
          break;
        case 'k':
          setCursor((c) => Math.max(c - 1, 0));
          break;
        case 'Enter':
        case 'o':
          if (!threadId && visible[cursor]) open(visible[cursor]);
          break;
        case 'u':
        case 'Escape':
          if (threadId) closeThread();
          break;
        case 'e':
          void act(current, 'archive');
          break;
        case '#':
          void act(current, 'trash');
          break;
        case 's':
          void act(current, 'star');
          break;
        case 'x':
          if (!threadId && visible[cursor]) toggleSelected(visible[cursor].id);
          break;
        case 'r':
          if (last && account) compose(draftFor('reply', last, account.email, accountId));
          break;
        case 'a':
          if (last && account) compose(draftFor('replyAll', last, account.email, accountId));
          break;
        case 'f':
          if (last && account) compose(draftFor('forward', last, account.email, accountId));
          break;
        case 'c':
          compose();
          break;
        case '/':
          searchInput.current?.focus();
          break;
        default:
          return;
      }
      event.preventDefault();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, [visible, cursor, threadId, thread, current, act, open, closeThread, compose, account, accountId]);

  function onScroll(event: React.UIEvent<HTMLDivElement>) {
    const el = event.currentTarget;
    if (!loading && emails.length < total && el.scrollTop + el.clientHeight > el.scrollHeight - 300) void load(emails.length);
  }

  async function renameLabel(name: string) {
    const next = normalizeLabel(window.prompt(t('Rename the label "{{name}}" to', { name }), name) ?? '');
    if (!next || next === name) return;
    try {
      await post('/api/me/labels/rename', { from: name, to: next });
      await refreshLabels();
      // Navigating reloads the list by itself; reloading here as well would race with it
      // using the old label.
      if (label === name) navigate(`/mail/label:${encodeURIComponent(next)}`);
      else void load(0);
    } catch (err) {
      setNotice(errorText(err, t('Could not rename the label')));
    }
  }

  async function deleteLabel(name: string) {
    if (!window.confirm(t('Delete the label "{{name}}"? The messages themselves are kept.', { name }))) return;
    try {
      await del(`/api/me/labels?name=${encodeURIComponent(name)}`);
      await refreshLabels();
      if (label === name) navigate('/mail/inbox');
      else void load(0);
    } catch (err) {
      setNotice(errorText(err, t('Could not delete the label')));
    }
  }

  async function addFolder() {
    const name = (newFolder ?? '').trim();
    if (!name) return;
    try {
      await createMailbox(name);
      setNewFolder(null);
      await refreshMailboxes();
    } catch (err) {
      setNotice(errorText(err, t('Could not create the folder')));
    }
  }

  async function removeFolder(folder: Mailbox) {
    if (!window.confirm(t('Delete the folder "{{name}}" and every message in it?', { name: folder.name }))) return;
    try {
      await destroyMailbox(folder.id);
      if (mailbox?.id === folder.id) navigate('/mail/inbox');
      await refreshMailboxes();
    } catch (err) {
      setNotice(errorText(err, t('Could not delete the folder')));
    }
  }

  const drafts = byRole('drafts');
  const sent = byRole('sent');
  // The message list: rows are memoised and only those in view are rendered.
  const listScroll = useRef<HTMLDivElement>(null);
  const virtualizer = useVirtualizer({
    count: visible.length,
    getScrollElement: () => listScroll.current,
    estimateSize: () => (density === 'expanded' ? 76 : 37),
    overscan: 10,
    getItemKey: (index) => visible[index]?.id ?? index,
  });
  // Keyboard navigation (j/k) keeps the highlighted row in view.
  useEffect(() => {
    if (!threadId && cursor < visible.length) virtualizer.scrollToIndex(cursor, { align: 'auto' });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [cursor]);
  const labelColors = useMemo(() => Object.fromEntries(labelDetails.map((detail) => [detail.name, detail.color])), [labelDetails]);
  /** Opens the row menu; on a row of the selection it acts on the whole selection. */
  function openRowMenu(email: EmailSummary, x: number, y: number) {
    const count = allInFolder ? total : selected.has(email.id) ? selected.size : 1;
    setRowMenu({ email, x, y, count });
  }

  /** Carries out what was chosen in the row menu. */
  async function rowMenuPick(pick: RowMenuPick, { email, count }: RowMenuTarget) {
    if (count > 1) {
      if (pick.kind === 'move') void bulk('move', pick.mailbox.id);
      else if (pick.kind === 'label') void bulk('label', pick.name);
      else if (pick.kind === 'archive' || pick.kind === 'trash' || pick.kind === 'junk' || pick.kind === 'inbox' || pick.kind === 'read' || pick.kind === 'unread') void bulk(pick.kind);
      return;
    }
    try {
      switch (pick.kind) {
        case 'reply':
        case 'replyAll':
        case 'forward': {
          if (!account) return;
          const messages = (await getThread(email.threadId)).filter((e) => !e.keywords.$draft);
          const last = messages[messages.length - 1];
          if (last) compose(draftFor(pick.kind, last, account.email, accountId));
          return;
        }
        case 'move':
          return void dropOn({ mailbox: pick.mailbox }, email);
        case 'label': {
          const ids = await conversationIds(email);
          const { name, on } = pick;
          setEmails((current) => current.map((e) => (e.threadId === email.threadId ? { ...e, keywords: { ...e.keywords, [name]: on } } : e)));
          if (await performOrQueue({ type: 'keyword', ids, keyword: name, value: on })) {
            setOffline(true);
            setPending(pendingCount());
          }
          setNotice(on ? t('Labelled “{{name}}”', { name }) : t('Label “{{name}}” removed', { name }));
          void refreshLabels();
          return;
        }
        case 'snooze': {
          const ids = await conversationIds(email);
          await snooze(ids, pick.until);
          setEmails((current) => current.filter((e) => e.threadId !== email.threadId));
          if (threadId === email.threadId) closeThread();
          setNotice(t('Snoozed until {{value}}', { value: pick.until.toLocaleString(uiLocale(), { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) }));
          void refreshMailboxes();
          return;
        }
        case 'findFrom': {
          const sender = email.from?.[0]?.email;
          if (!sender) return;
          const query = `from:${sender}`;
          setSearch(query);
          setServerSearch(query);
          return;
        }
        case 'newTab':
          window.open(`/mail/${slug}/${email.threadId}`, '_blank', 'noopener');
          return;
        default:
          return void act(email, pick.kind);
      }
    } catch (err) {
      setNotice(errorText(err, t('The action failed')));
    }
  }

  // Rows get one unchanging object of callbacks; it reaches the latest page state through a ref.
  const rowState = useRef({ act, open, toggleSelected, openRowMenu });
  rowState.current = { act, open, toggleSelected, openRowMenu };
  const rowHandlers = useMemo<RowHandlers>(
    () => ({
      open: (email, index) => {
        setCursor(index);
        rowState.current.open(email);
      },
      toggleSelected: (id) => rowState.current.toggleSelected(id),
      act: (email, action) => void rowState.current.act(email, action),
      dragStart: (email, event) => {
        dragged.current = email;
        event.dataTransfer.effectAllowed = 'move';
        event.dataTransfer.setData('text/plain', email.subject);
      },
      dragEnd: () => {
        dragged.current = null;
        setDropTarget(null);
      },
      preview: (file) => setPreview(file),
      contextMenu: (email, event) => {
        // Shift keeps the browser's own menu within reach, as in Gmail.
        if (event.shiftKey) return;
        event.preventDefault();
        rowState.current.openRowMenu(email, event.clientX, event.clientY);
      },
    }),
    [],
  );

  const wrapNav = (nav: ReactElement) =>
    compact ? (
      <SwipeableDrawer open={drawerOpen} onOpen={() => setDrawerOpen(true)} onClose={() => setDrawerOpen(false)} {...SWIPE} ModalProps={{ keepMounted: true }} slotProps={{ paper: { sx: { bgcolor: 'background.default' } } }}>
        {nav}
      </SwipeableDrawer>
    ) : (
      nav
    );

  return (
    <Box sx={{ height: '100vh', display: 'flex', flexDirection: 'column', bgcolor: 'background.default' }}>
      <TopBar
        title={t('unoMail')}
        onHome={() => setSearch('')}
        leading={
          compact ? (
            <IconButton sx={ABOVE_SWIPE} aria-label={t('Toggle sidebar')} aria-expanded={drawerOpen} onClick={() => setDrawerOpen((open) => !open)}><MenuIcon /></IconButton>
          ) : (
            <IconButton aria-label={t('Toggle sidebar')} aria-expanded={sidebar} onClick={() => setSidebar((s) => !s)}><MenuIcon /></IconButton>
          )
        }
      >
        <Paper
          ref={searchBox}
          component="form"
          elevation={0}
          onSubmit={(e) => {
            e.preventDefault();
            // Enter searches at once, without waiting for the pause in typing.
            setServerSearch(search.trim());
          }}
          sx={{ display: 'flex', alignItems: 'center', pl: 2, pr: 0.5, borderRadius: 999, maxWidth: 720, bgcolor: 'm3.surfaceContainerHigh', transition: (theme) => theme.transitions.create(['background-color', 'box-shadow']), '&:focus-within': { bgcolor: 'background.paper', boxShadow: 2 } }}
        >
          <Search color="action" />
          <InputBase inputRef={searchInput} value={search} onChange={(e) => setSearch(e.target.value)} placeholder={t('Search mail')} inputProps={{ 'aria-label': t('Search mail') }} sx={{ ml: 1.5, flex: 1, height: 48 }} />
          <Tooltip title={t('Show search options')}>
            <IconButton aria-label={t('Show search options')} aria-haspopup="dialog" aria-expanded={Boolean(searchPanel)} onClick={() => setSearchPanel(searchBox.current)}>
              <Tune />
            </IconButton>
          </Tooltip>
        </Paper>
        <AdvancedSearch
          anchor={searchPanel}
          query={search}
          folders={ownMailboxes.map((m) => ({ value: m.role ?? m.name, label: folderName(m) }))}
          onClose={() => setSearchPanel(null)}
          onSearch={(query) => {
            setSearchPanel(null);
            setSearch(query);
            setServerSearch(query);
          }}
        />
      </TopBar>
      <Box sx={{ flex: 1, display: 'flex', minHeight: 0 }}>
        {wrapNav(
          <MailSidebar
            mini={mini}
            compact={compact}
            scheduledCount={scheduledCount}
            label={label}
            mailbox={mailbox}
            ownMailboxes={ownMailboxes}
            sharedMailboxes={sharedMailboxes}
            allMail={allMail}
            subscriptionsPage={subscriptionsPage}
            labels={labels}
            labelColor={labelColor}
            sidebarLinks={plugins.sidebarLinks}
            account={account}
            linkTo={linkTo}
            dropProps={dropProps}
            dropStyle={dropStyle}
            onCompose={() => { setDrawerOpen(false); compose(); }}
            onFolderMenu={(anchor, mailbox) => setFolderMenu({ anchor, mailbox })}
            onNewFolder={() => setNewFolder('')}
            onLabelDialog={setLabelDialog}
            onRenameLabel={(name) => void renameLabel(name)}
            onDeleteLabel={(name) => void deleteLabel(name)}
          />,
        )}
        {subscriptionsPage ? <Subscriptions /> : (
        <Paper elevation={0} sx={{ width: { xs: '100%', md: threadId ? 400 : '100%' }, flexShrink: { md: threadId ? 0 : 1 }, flex: threadId ? undefined : 1, display: { xs: threadId ? 'none' : 'flex', md: 'flex' }, flexDirection: 'column', bgcolor: 'transparent', mx: { xs: 1, md: 0 }, mr: { md: 1 }, overflow: 'hidden', minWidth: 0 }}>
          <ListToolbar
            heading={serverSearch ? t('Results for "{{serverSearch}}"', { serverSearch }) : label ? t('Label: {{label}}', { label }) : allMail ? t('All mail') : (mailbox ? folderName(mailbox) : '')}
            visible={visible}
            total={total}
            selected={selected}
            allInFolder={allInFolder}
            inJunk={mailbox?.role === 'junk'}
            folders={mailboxes.filter((m) => m.id !== mailbox?.id && (!m.shareOwner || m.myRights?.mayAddItems))}
            labels={labels}
            labelColor={labelColor}
            onSelect={(ids) => { setAllInFolder(false); setSelected(ids); }}
            onBulk={(action, argument, all) => void bulk(action, argument, all)}
            onRefresh={() => { void load(0); void refreshMailboxes(); }}
          />
          {selected.size > 0 && visible.every((e) => selected.has(e.id)) && total > visible.length && (
            <Alert severity="info" icon={false} sx={{ borderRadius: 0, py: 0 }}>
              {allInFolder ? t('All {{total}} conversations here are selected. ', { total }) : t('The {{length}} conversations shown are selected. ', { length: visible.length })}
              <Button size="small" onClick={() => (allInFolder ? (setSelected(new Set()), setAllInFolder(false)) : setAllInFolder(true))}>
                {allInFolder ? t('Clear selection') : t('Select all {{total}}', { total })}
              </Button>
            </Alert>
          )}
          {categorised && !serverSearch && (
            <CategoryTabs category={category} onChange={setCategoryTab} counts={counts} latest={latest} dropProps={dropProps} dropStyle={dropStyle} />
          )}
          {loading && <LinearProgress />}
          {offline && (
            <Alert severity="warning" sx={{ borderRadius: 0 }}>
              {t('You are offline. Showing the copy saved on this device.')}{pending > 0 ? ` ${t('{{count}} changes waiting to be synchronised.', { count: pending })}` : ''}
            </Alert>
          )}
          <Box ref={listScroll} sx={{ flex: 1, overflow: 'auto', pb: 1, borderRadius: '16px 16px 0 0' }} onScroll={onScroll}>
            {/* Only the rows in view (and a few around them) exist; the list keeps its full height. */}
            <List disablePadding aria-label={t('Messages')} style={{ position: 'relative', height: virtualizer.getTotalSize() }}>
              {virtualizer.getVirtualItems().map((item) => {
                const email = visible[item.index];
                return (
                  <div key={email.id} data-index={item.index} ref={virtualizer.measureElement} style={{ position: 'absolute', top: 0, left: 0, width: '100%', paddingBottom: 2, transform: `translateY(${item.start}px)` }}>
                    <EmailRow
                      email={email}
                      index={item.index}
                      accountId={accountId}
                      // A phone has room for one column only: sender and date, then subject and text.
                      density={phone ? 'expanded' : density}
                      narrow={Boolean(threadId) || phone}
                      showRecipients={mailbox?.role === 'sent' || mailbox?.role === 'drafts'}
                      chosen={allInFolder || selected.has(email.id)}
                      highlighted={threadId ? email.threadId === threadId : item.index === cursor}
                      first={item.index === 0}
                      last={item.index === visible.length - 1}
                      labelColors={labelColors}
                      canArchive={mailbox?.role !== 'archive' && Boolean(byRole('archive'))}
                      inTrash={mailbox?.role === 'trash'}
                      handlers={rowHandlers}
                    />
                  </div>
                );
              })}
            </List>
            {!loading && visible.length === 0 && (
              <Typography sx={{ color: 'text.secondary', p: 4, textAlign: 'center' }}>
                {search ? t('No messages match your search.') : t('Nothing here yet.')}
              </Typography>
            )}
            {loading && emails.length > 0 && <Box sx={{ p: 2, textAlign: 'center' }}><CircularProgress size={24} /></Box>}
          </Box>
        </Paper>
        )}
        {threadId && (
          <Paper elevation={0} sx={{ flex: 1, minWidth: 0, borderRadius: { xs: 0, sm: 1.5 }, mx: { xs: 0, sm: 1, md: 0 }, mr: { md: 1 }, mb: { xs: 0, sm: 1 }, overflow: 'hidden' }}>
            <Reader
              emails={thread}
              accountId={accountId}
              ownEmail={account?.email ?? ''}
              inboxId={byRole('inbox')?.id ?? ''}
              onBack={closeThread}
              onArchive={() => void act(current, 'archive')}
              onDelete={() => void act(current, 'trash')}
              onJunk={() => void act(current, 'junk')}
              onNotSpam={mailbox?.role === 'junk' ? () => void act(current, 'inbox') : undefined}
              onMarkUnread={() => void act(current, 'unread')}
              onSnooze={async (until) => {
                const ids = (thread ?? []).filter((e) => !e.keywords.$draft && !e.keywords.$scheduled).map((e) => e.id);
                try {
                  await snooze(ids, until);
                  setNotice(t('Snoozed until {{value}}', { value: until.toLocaleString(uiLocale(), { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) }));
                  closeThread();
                  void refreshMailboxes();
                  void load(0);
                } catch (err) {
                  setNotice(errorText(err, t('The conversation could not be snoozed')));
                }
              }}
              onCancelScheduled={async (emailId) => {
                try {
                  const pending = (await listScheduled()).find((s) => s.emailId === emailId);
                  if (pending) await cancelSubmission(pending.id);
                  setNotice(t('Sending cancelled. The message is in Drafts'));
                  setScheduledCount((n) => Math.max(0, n - 1));
                  closeThread();
                  void load(0);
                } catch (err) {
                  setNotice(errorText(err, t('Sending could not be cancelled')));
                }
              }}
              labels={labels}
              onToggleLabel={(name, on) => void toggleLabel(name, on)}
              onAction={(action, email, suggestedText) => {
                if (!account) return;
                if (suggestedText && draft) { setNotice(t('Close the current draft before choosing a suggested reply.')); return; }
                compose(draftFor(action, email, account.email, accountId, suggestedText));
              }}
            />
          </Paper>
        )}
      </Box>
      {compact && !threadId && !draft && (
        <Fab variant={phone ? 'circular' : 'extended'} color="primary" aria-label={t('Compose')} onClick={() => compose()} sx={{ position: 'fixed', right: 16, bottom: 16, zIndex: 1050 }}>
          <Edit />
          {!phone && t('Compose')}
        </Fab>
      )}
      {draft && drafts && sent && (
        <Composer
          key={draft.key}
          initial={draft.draft}
          accountId={accountId}
          draftsId={drafts.id}
          sentId={sent.id}
          draftEmailId={draft.emailId}
          onClose={(wasSent, wasQueued, info) => {
            setDraft(null);
            if (wasQueued) {
              setOffline(true);
              setPending(pendingCount());
              setNotice(t('You are offline. The message will be sent when the connection returns'));
            } else if (info?.scheduledAt) {
              setNotice(t('Scheduled for {{value}}', { value: info.scheduledAt.toLocaleString(uiLocale(), { weekday: 'short', day: 'numeric', month: 'short', hour: '2-digit', minute: '2-digit' }) }));
              void listScheduled().then((list) => setScheduledCount(list.length), () => {});
            } else if (info?.submissionId && info.undoSeconds) setUndoable(info);
            else if (wasSent) setNotice(t('Message sent'));
            void refreshMailboxes();
            void load(0);
          }}
        />
      )}
      <Dialog open={newFolder !== null} onClose={() => setNewFolder(null)} fullWidth maxWidth="xs">
        <DialogTitle>{t('New folder')}</DialogTitle>
        <DialogContent>
          <TextField autoFocus fullWidth label={t('Folder name')} value={newFolder ?? ''} onChange={(e) => setNewFolder(e.target.value)} onKeyDown={(e) => e.key === 'Enter' && void addFolder()} sx={{ mt: 1 }} />
        </DialogContent>
        <DialogButtons onCancel={() => setNewFolder(null)} onConfirm={() => void addFolder()} label={t('Create')} />
      </Dialog>
      <RowMenu
        target={rowMenu}
        folders={mailboxes.filter((m) => m.id !== mailbox?.id && (!m.shareOwner || m.myRights?.mayAddItems))}
        labels={labels}
        labelColor={labelColor}
        canArchive={mailbox?.role !== 'archive' && Boolean(byRole('archive'))}
        inTrash={mailbox?.role === 'trash'}
        inJunk={mailbox?.role === 'junk'}
        onPick={(pick, target) => void rowMenuPick(pick, target)}
        onClose={() => setRowMenu(null)}
      />
      {labelDialog && (
        <LabelDialog
          value={labelDialog}
          onChange={setLabelDialog}
          onClose={() => setLabelDialog(null)}
          onSave={(name, color) => {
            setLabelDialog(null);
            void saveLabel(name, color)
              .then(refreshLabels)
              .then(() => setNotice(labelDialog.existing ? t('Label updated') : t('Label “{{name}}” created', { name })))
              .catch((err) => setNotice(errorText(err, t('The label could not be saved'))));
          }}
        />
      )}
      <Menu anchorEl={folderMenu?.anchor} open={Boolean(folderMenu)} onClose={() => setFolderMenu(null)}>
        {folderMenu && !folderMenu.mailbox.shareOwner && (
          <MenuItem onClick={() => { setSharing(folderMenu.mailbox); setFolderMenu(null); }}>{t('Share…')}</MenuItem>
        )}
        {folderMenu && (
          <MenuItem component="a" href={exportUrl(folderMenu.mailbox.id)} download onClick={() => setFolderMenu(null)}>
            {t('Export as mbox')}
          </MenuItem>
        )}
        {folderMenu && (!folderMenu.mailbox.shareOwner || folderMenu.mailbox.myRights?.mayAddItems) && (
          <MenuItem onClick={() => { importTarget.current = folderMenu.mailbox; setFolderMenu(null); importInput.current?.click(); }}>{t('Import messages…')}</MenuItem>
        )}
        {folderMenu && !folderMenu.mailbox.role && !folderMenu.mailbox.shareOwner && (
          <MenuItem onClick={() => { const target = folderMenu.mailbox; setFolderMenu(null); void removeFolder(target); }}>{t('Delete folder')}</MenuItem>
        )}
      </Menu>
      <input ref={importInput} type="file" accept=".eml,.mbox,message/rfc822,application/mbox" hidden aria-label={t('Messages to import')} onChange={(e) => { void importInto(e.target.files?.[0]); e.target.value = ''; }} />
      {sharing && (
        <ShareDialog
          mailbox={sharing}
          onClose={(changed) => {
            setSharing(null);
            if (changed) void refreshMailboxes();
          }}
        />
      )}
      {preview && <AttachmentPreview file={preview} onClose={() => setPreview(null)} />}
      <Snackbar open={Boolean(notice)} autoHideDuration={4000} onClose={() => setNotice('')} message={notice} />
      <Snackbar
        open={Boolean(undoable)}
        autoHideDuration={(undoable?.undoSeconds ?? 0) * 1000}
        onClose={(_, reason) => { if (reason !== 'clickaway') setUndoable(null); }}
        message={t('Message sent')}
        action={
          <Button
            color="secondary"
            size="small"
            onClick={async () => {
              const info = undoable;
              setUndoable(null);
              if (!info?.submissionId) return;
              try {
                await cancelSubmission(info.submissionId);
                // Back in the composer, continuing the same draft.
                setDraft({ key: Date.now(), draft: { ...info.draft }, emailId: info.emailId });
                setNotice(t('Sending undone'));
              } catch (err) {
                setNotice(errorText(err, t('The message could not be called back')));
              }
            }}
          >
            {t('Undo')}
          </Button>
        }
      />
    </Box>
  );
}
