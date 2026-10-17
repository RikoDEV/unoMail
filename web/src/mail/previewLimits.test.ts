import { describe, expect, it } from 'vitest';
import { previewScale, readPreview } from './previewLimits';

describe('bounded attachment previews', () => {
  it('rejects an oversized stream even without a content length and cancels it', async () => {
    let cancelled = false;
    const response = new Response(new ReadableStream({
      pull(controller) { controller.enqueue(new Uint8Array(8)); },
      cancel() { cancelled = true; },
    }));
    await expect(readPreview(response, 10)).rejects.toThrow('too large');
    expect(cancelled).toBe(true);
  });
  it('bounds extreme PDF page dimensions and total canvas area', () => {
    for (const [width, height] of [[1e8, 1], [1, 1e8], [1e8, 1e8], [600, 800]]) {
      const scale = previewScale(width, height, 40);
      expect(width * scale).toBeLessThanOrEqual(4096);
      expect(height * scale).toBeLessThanOrEqual(4096);
      expect(width * height * scale ** 2 * 40).toBeLessThanOrEqual(16_000_001);
    }
    expect(() => previewScale(Infinity, 1, 1)).toThrow();
  });
});
