import { describe, expect, it } from 'vitest';
import { adaptForDark, contrast, darken, lighten, parseColor, type Rgb } from './darkColors';

const DARK: Rgb = [29, 27, 32];

describe('dark theme colours', () => {
  it('parses computed colours and ignores transparent ones', () => {
    expect(parseColor('rgb(1, 2, 3)')).toEqual([1, 2, 3]);
    expect(parseColor('rgba(10, 20, 30, 0.9)')).toEqual([10, 20, 30]);
    expect(parseColor('rgba(0, 0, 0, 0)')).toBeNull();
    expect(parseColor('transparent')).toBeNull();
  });

  it('lightens faint text until it reads, keeping its hue', () => {
    for (const color of [[0, 0, 0], [51, 51, 51], [0, 0, 139], [120, 20, 20]] as Rgb[]) {
      expect(contrast(lighten(color, DARK), DARK)).toBeGreaterThanOrEqual(4.5);
    }
    const [r, , b] = lighten([0, 0, 139], DARK);
    expect(b).toBeGreaterThan(r);
  });

  it('fixes dark text on the dark page but leaves the message’s own light backgrounds alone', () => {
    document.body.style.backgroundColor = 'rgb(29, 27, 32)';
    document.body.innerHTML = `
      <p id="black" style="color: rgb(0, 0, 0)">Black text</p>
      <div style="background-color: rgb(255, 255, 255)"><p id="card" style="color: rgb(0, 0, 0)">On a white card</p></div>
      <p id="light" style="color: rgb(230, 230, 230)">Already light</p>`;
    adaptForDark(document, DARK);
    const color = (id: string) => parseColor(getComputedStyle(document.getElementById(id)!).color)!;
    expect(contrast(color('black'), DARK)).toBeGreaterThanOrEqual(4.5);
    expect(color('card')).toEqual([0, 0, 0]);
    expect(color('light')).toEqual([230, 230, 230]);
  });

  it('darkens text left light by the dark page on the message’s own light backgrounds', () => {
    // The frame's dark-theme defaults: light text and links on the dark page.
    document.body.style.cssText = 'background-color: rgb(29, 27, 32); color: rgb(230, 224, 233)';
    document.body.innerHTML = `
      <table style="background-color: rgb(255, 255, 255)"><tbody><tr><td id="default">Newsletter text without a colour of its own</td></tr></tbody></table>
      <div style="background-color: rgb(250, 250, 250)"><a id="link" href="#" style="color: rgb(208, 188, 255)">Read more</a></div>
      <div style="background-image: url(data:image/png;base64,AA==)"><p id="image">Text on a picture</p></div>
      <p id="page">Default text on the page</p>`;
    adaptForDark(document, DARK);
    const color = (id: string) => parseColor(getComputedStyle(document.getElementById(id)!).color)!;
    expect(contrast(color('default'), [255, 255, 255])).toBeGreaterThanOrEqual(4.5);
    expect(contrast(color('link'), [250, 250, 250])).toBeGreaterThanOrEqual(4.5);
    const [r, , b] = color('link');
    expect(b).toBeGreaterThan(r);
    expect(color('image')).toEqual([230, 224, 233]);
    expect(color('page')).toEqual([230, 224, 233]);
  });

  it('darkens faint colours until they read on light backgrounds', () => {
    for (const color of [[255, 255, 255], [230, 224, 233], [208, 188, 255], [255, 255, 0]] as Rgb[]) {
      expect(contrast(darken(color, [255, 255, 255]), [255, 255, 255])).toBeGreaterThanOrEqual(4.5);
    }
  });
});
