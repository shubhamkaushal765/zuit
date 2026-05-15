import React, {useEffect, type ReactNode} from 'react';
import {useLocation} from '@docusaurus/router';

const DIMENSION_TOKEN: Record<string, string> = {
  maintainability: 'var(--cl-dimension-maintainability)',
  security:        'var(--cl-dimension-security)',
  complexity:      'var(--cl-dimension-complexity)',
  documentation:   'var(--cl-dimension-documentation)',
  'test smell':    'var(--cl-dimension-test)',
  test:            'var(--cl-dimension-test)',
  testsmell:       'var(--cl-dimension-test)',
};

/**
 * Reads the Dimension cell from a rule page's leading metadata table and sets
 * `--cl-rule-band` on that table so the CSS-only header treatment colors its
 * top border by dimension. Pages without a matching dimension keep the
 * `--cl-accent-primary` default declared in custom.css.
 *
 * Implementation is purely progressive — any throw is swallowed so a page
 * always renders, just without the dimension-colored band.
 */
function applyRuleBand(pathname: string): void {
  try {
    if (typeof document === 'undefined') return;
    if (!pathname.startsWith('/zuit/rules/') && !pathname.startsWith('/rules/')) return;

    const table = document.querySelector<HTMLTableElement>(
      '.theme-doc-markdown > table:first-of-type',
    );
    if (!table) return;

    const headers = Array.from(
      table.querySelectorAll<HTMLTableCellElement>('thead th'),
    ).map((th) => (th.textContent ?? '').trim().toLowerCase());
    if (headers.length !== 2 || headers[0] !== 'property' || headers[1] !== 'value') {
      return;
    }
    table.setAttribute('data-rule-meta', '');

    const rows = table.querySelectorAll<HTMLTableRowElement>('tbody tr');
    for (const row of rows) {
      const label = (row.children[0]?.textContent ?? '').trim().toLowerCase();
      if (label !== 'dimension') continue;
      const raw = (row.children[1]?.textContent ?? '').trim().toLowerCase();
      const key = raw.replace(/[_-]/g, ' ');
      const token = DIMENSION_TOKEN[key] ?? DIMENSION_TOKEN[raw];
      if (token) table.style.setProperty('--cl-rule-band', token);
      break;
    }
  } catch {
    /* no-op: degrade to default band color */
  }
}

export default function Root({children}: {children: ReactNode}): ReactNode {
  const {pathname} = useLocation();
  useEffect(() => {
    applyRuleBand(pathname);
  }, [pathname]);
  return <>{children}</>;
}
