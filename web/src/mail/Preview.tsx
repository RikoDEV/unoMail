// In-browser previews of attachments: images, plain text and PDF.
//
// Attachment content is untrusted. Text is only ever shown as text (HTML files too), images
// are limited to formats browsers decode safely, and PDFs are drawn onto canvases by pdf.js,
// which neither runs scripts embedded in the document nor follows its links.

import Download from '@mui/icons-material/Download';
import { Alert, Box, Button, CircularProgress, Dialog, DialogActions, DialogContent, DialogTitle, Typography } from '@mui/material';
import { useEffect, useRef, useState } from 'react';
import { formatBytes, errorText } from '../lib/api';
import { previewScale, readPreview } from './previewLimits';
import type { PDFDocumentLoadingTask, RenderTask } from 'pdfjs-dist';

import { t } from '../i18n';
export interface PreviewFile {
  name: string;
  type: string;
  /** Where the content can be fetched from (a download address or a blob URL). */
  url: string;
}

export type PreviewKind = 'image' | 'text' | 'pdf';

const TEXT_EXTENSIONS = ['txt', 'log', 'md', 'csv', 'tsv', 'json', 'xml', 'yml', 'yaml', 'ini', 'conf', 'cfg', 'html', 'htm', 'css', 'js', 'ts', 'sh', 'py', 'rs', 'sql', 'diff', 'patch', 'ics', 'vcf', 'eml'];
const TEXT_TYPES = ['application/json', 'application/xml', 'application/x-yaml', 'application/sql', 'message/rfc822', 'application/x-sh'];
const MAX_TEXT_BYTES = 2 * 1024 * 1024;
const PDF_PAGE_BATCH = 10;
const MAX_PDF_PAGES = 40;

/** How a file can be previewed, judged by its declared type and its name. */
export function previewKind(file: { name?: string | null; type: string }): PreviewKind | null {
  const type = file.type.toLowerCase();
  const extension = (file.name ?? '').toLowerCase().split('.').pop() ?? '';
  if (type === 'application/pdf' || extension === 'pdf') return 'pdf';
  if (['image/png', 'image/jpeg', 'image/gif', 'image/webp'].includes(type)) return 'image';
  // Senders often label text files as generic binary data; the name decides then.
  if (type.startsWith('text/') || TEXT_TYPES.includes(type) || ((type === 'application/octet-stream' || type === '') && TEXT_EXTENSIONS.includes(extension))) return 'text';
  return null;
}

function PdfPages({ data }: { data: Uint8Array }) {
  const container = useRef<HTMLDivElement>(null);
  const [pages, setPages] = useState(0);
  const [shown, setShown] = useState(0);
  const [error, setError] = useState('');
  const [limit, setLimit] = useState(PDF_PAGE_BATCH);

  useEffect(() => {
    let cancelled = false;
    let loadingTask: PDFDocumentLoadingTask | undefined;
    let renderTask: RenderTask | undefined;
    const holder = container.current;
    const timer = window.setTimeout(() => {
      cancelled = true;
      renderTask?.cancel();
      void loadingTask?.destroy();
      setError(t('This PDF cannot be displayed. Download it to open it.'));
    }, 30_000);
    (async () => {
      try {
        const pdfjs = await import('pdfjs-dist');
        const worker = await import('pdfjs-dist/build/pdf.worker.min.mjs?url');
        if (cancelled) return;
        pdfjs.GlobalWorkerOptions.workerSrc = worker.default;
        // A copy: the library takes ownership of the buffer it is given.
        loadingTask = pdfjs.getDocument({ data: data.slice(), enableXfa: false, disableAutoFetch: true, maxImageSize: 16_000_000, canvasMaxAreaInBytes: 64_000_000 });
        const document = await loadingTask.promise;
        if (cancelled || !holder) return;
        setPages(document.numPages);
        holder.replaceChildren();
        for (let number = 1; number <= Math.min(document.numPages, limit); number += 1) {
          const page = await document.getPage(number);
          if (cancelled) return;
          const base = page.getViewport({ scale: 1 });
          const viewport = page.getViewport({ scale: previewScale(base.width, base.height, Math.min(document.numPages, limit)) });
          const canvas = window.document.createElement('canvas');
          canvas.width = viewport.width;
          canvas.height = viewport.height;
          canvas.setAttribute('aria-label', `Page ${number}`);
          canvas.setAttribute('role', 'img');
          canvas.style.cssText = 'display:block;max-width:100%;height:auto;margin:0 auto 12px;box-shadow:0 0 0 1px rgba(128,128,128,.4);background:#fff';
          holder.append(canvas);
          renderTask = page.render({ canvas, viewport });
          await renderTask.promise;
          page.cleanup();
          if (!cancelled) setShown(number);
        }
      } catch (err) {
        if (!cancelled) setError(err instanceof Error && /password/i.test(err.message) ? t('This PDF is password-protected. Download it to open it.') : t('This PDF cannot be displayed. Download it to open it.'));
      } finally { window.clearTimeout(timer); }
    })();
    return () => {
      cancelled = true;
      window.clearTimeout(timer);
      renderTask?.cancel();
      void loadingTask?.destroy();
      holder?.replaceChildren();
    };
  }, [data, limit]);

  if (error) return <Alert severity="warning">{error}</Alert>;
  return (
    <>
      <div ref={container} data-testid="pdf-pages" data-pages-rendered={shown} />
      {pages === 0 && <CircularProgress size={24} />}
      {pages > limit && limit < MAX_PDF_PAGES && (
        <Box sx={{ textAlign: 'center' }}>
          <Button onClick={() => setLimit((current) => Math.min(MAX_PDF_PAGES, current + PDF_PAGE_BATCH))}>
            {t('Show more pages ({{limit}} of {{pages}})', { limit, pages })}
          </Button>
        </Box>
      )}
      {pages > MAX_PDF_PAGES && limit >= MAX_PDF_PAGES && <Alert severity="info">Download the document to read the remaining pages.</Alert>}
    </>
  );
}

/** A dialog showing the content of one attachment. */
export function AttachmentPreview({ file, onClose }: { file: PreviewFile; onClose: () => void }) {
  const kind = previewKind(file);
  const [content, setContent] = useState<{ text?: string; truncated?: boolean; imageUrl?: string; pdf?: Uint8Array; size: number } | null>(null);
  const [error, setError] = useState('');

  useEffect(() => {
    let cancelled = false;
    let created = '';
    const controller = new AbortController();
    const timer = window.setTimeout(() => controller.abort(), 30_000);
    setContent(null);
    setError('');
    (async () => {
      try {
        const response = await fetch(file.url, { credentials: 'same-origin', signal: controller.signal });
        if (!response.ok) throw new Error(t('The attachment could not be loaded.'));
        const blob = await readPreview(response);
        if (cancelled) return;
        if (kind === 'text') {
          const bytes = new Uint8Array(await blob.slice(0, MAX_TEXT_BYTES).arrayBuffer());
          setContent({ text: new TextDecoder('utf-8', { fatal: false }).decode(bytes), truncated: blob.size > MAX_TEXT_BYTES, size: blob.size });
        } else if (kind === 'image') {
          // Re-typed from the declared image type, so nothing else can be smuggled in as one.
          created = URL.createObjectURL(new Blob([blob], { type: file.type.toLowerCase() }));
          setContent({ imageUrl: created, size: blob.size });
        } else if (kind === 'pdf') {
          setContent({ pdf: new Uint8Array(await blob.arrayBuffer()), size: blob.size });
        }
      } catch (err) {
        if (!cancelled) setError(errorText(err, t('The attachment could not be loaded.')));
      } finally { window.clearTimeout(timer); }
    })();
    return () => {
      cancelled = true;
      controller.abort();
      window.clearTimeout(timer);
      if (created) URL.revokeObjectURL(created);
    };
  }, [file.url, file.type, kind]);

  return (
    <Dialog open onClose={onClose} fullWidth maxWidth="lg">
      <DialogTitle sx={{ overflowWrap: 'anywhere' }}>
        {file.name}
        {content && (
          <Typography component="span" variant="body2" sx={{ color: 'text.secondary', ml: 1 }}>
            {formatBytes(content.size)}
          </Typography>
        )}
      </DialogTitle>
      <DialogContent dividers sx={{ minHeight: 200, bgcolor: kind === 'pdf' ? 'action.hover' : undefined }}>
        {error && <Alert severity="error">{error}</Alert>}
        {!error && !content && <CircularProgress size={24} />}
        {content?.text !== undefined && (
          <>
            {content.truncated && <Alert severity="info" sx={{ mb: 1 }}>{t('Only the first 2 MB are shown. Download the file to see all of it.')}</Alert>}
            <Box component="pre" data-testid="text-preview" sx={{ m: 0, whiteSpace: 'pre-wrap', overflowWrap: 'anywhere', fontFamily: 'monospace', fontSize: 13 }}>
              {content.text}
            </Box>
          </>
        )}
        {content?.imageUrl && <Box component="img" src={content.imageUrl} alt={file.name} sx={{ display: 'block', maxWidth: '100%', mx: 'auto' }} />}
        {content?.pdf && <PdfPages data={content.pdf} />}
      </DialogContent>
      <DialogActions>
        <Button component="a" href={file.url} download={file.name} startIcon={<Download />}>
          {t('Download')}
        </Button>
        <Button onClick={onClose}>{t('Close')}</Button>
      </DialogActions>
    </Dialog>
  );
}
