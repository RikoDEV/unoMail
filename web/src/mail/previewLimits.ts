const MAX_PREVIEW_BYTES = 50 * 1024 * 1024;

/** Bound the allocation while reading, not after response.blob() has buffered it. */
export async function readPreview(response: Response, limit = MAX_PREVIEW_BYTES): Promise<Blob> {
  if (Number(response.headers.get('content-length')) > limit) {
    await response.body?.cancel();
    throw new Error('This file is too large to preview. Download it instead.');
  }
  if (!response.body) throw new Error('The attachment could not be loaded.');
  const reader = response.body.getReader();
  const chunks: ArrayBuffer[] = [];
  let size = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return new Blob(chunks);
      size += value.byteLength;
      if (size > limit) throw new Error('This file is too large to preview. Download it instead.');
      chunks.push(value.slice().buffer);
    }
  } finally {
    await reader.cancel().catch(() => {});
    reader.releaseLock();
  }
}

/** A bounded page area and dimension, including extremely tall/narrow pages. */
export function previewScale(width: number, height: number, pages: number): number {
  if (![width, height].every((n) => Number.isFinite(n) && n > 0)) throw new Error('Invalid page dimensions');
  return Math.min(1.5, 4096 / width, 4096 / height, Math.sqrt(16_000_000 / Math.max(1, pages) / width / height));
}
