import { ThemeProvider } from '@mui/material';
import { act, createElement } from 'react';
import { createRoot } from 'react-dom/client';
import { describe, expect, it } from 'vitest';
import { LinearProgress } from './progress';
import { BUILT_IN_SKINS, buildTheme } from './skins';

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

function render(props: Parameters<typeof LinearProgress>[0]): HTMLElement {
  const host = document.createElement('div');
  const root = createRoot(host);
  act(() => root.render(createElement(ThemeProvider, { theme: buildTheme(BUILT_IN_SKINS[0], '#6750a4', false) }, createElement(LinearProgress, props))));
  return host.querySelector('[role="progressbar"]')!;
}

describe('linear progress', () => {
  it('reports a determinate value and splits active part, track and stop indicator', () => {
    const bar = render({ variant: 'determinate', value: 42.4, 'aria-label': 'Storage' });
    expect(bar.getAttribute('aria-valuenow')).toBe('42');
    expect(bar.getAttribute('aria-label')).toBe('Storage');
    // Active segment, then the track holding the stop dot.
    expect(bar.children).toHaveLength(2);
    expect(bar.children[1].children).toHaveLength(1);
  });

  it('draws no track when full and no active part when empty', () => {
    expect(render({ variant: 'determinate', value: 100 }).children).toHaveLength(1);
    expect(render({ variant: 'determinate', value: 0 }).querySelectorAll('div')).toHaveLength(2);
  });

  it('has no value while indeterminate', () => {
    expect(render({}).hasAttribute('aria-valuenow')).toBe(false);
  });
});
