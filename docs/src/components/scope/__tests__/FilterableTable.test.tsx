import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import FilterableTable from '../FilterableTable';

interface Row { id: string; name: string; family: 'A' | 'B' }

const ROWS: Row[] = [
  { id: 'A001', name: 'alpha-one', family: 'A' },
  { id: 'A002', name: 'alpha-two', family: 'A' },
  { id: 'B001', name: 'beta-one',  family: 'B' },
];

const COLUMNS = [
  { key: 'id' as const,     header: 'ID',     searchable: true },
  { key: 'name' as const,   header: 'Name' },
  { key: 'family' as const, header: 'Family' },
];

const FILTERS = [
  { value: 'all', label: 'All' },
  { value: 'A',   label: 'Family A' },
  { value: 'B',   label: 'Family B' },
];

describe('FilterableTable — rendering', () => {
  it('renders one column header per column', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    ['ID', 'Name', 'Family'].forEach(h => expect(screen.getByText(h)).toBeInTheDocument());
  });

  it('renders one row per data row by default', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    // 1 header row + 3 data rows
    expect(screen.getAllByRole('row')).toHaveLength(4);
  });

  it('respects a custom column render fn', () => {
    const cols = [
      ...COLUMNS,
      { key: 'tag', header: 'Tag', render: (r: Row) => <em>{r.family}-x</em> },
    ];
    render(<FilterableTable rows={ROWS} columns={cols as any} filterField="family" filterOptions={FILTERS} />);
    expect(screen.getAllByText('A-x')[0]).toBeInTheDocument();
  });

  it('uses caption as accessible <table> caption when provided', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} caption="Test caption" />);
    expect(screen.getByRole('table')).toHaveAccessibleName('Test caption');
  });
});

describe('FilterableTable — pill filtering', () => {
  it('filters rows by equality on filterField when a non-all pill is active', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    await user.click(screen.getByRole('radio', { name: 'Family A' }));
    expect(screen.getAllByRole('row')).toHaveLength(3); // header + 2 A rows
    expect(screen.queryByText('beta-one')).not.toBeInTheDocument();
  });

  it('honors initialFilter on first render', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} initialFilter="B" />);
    expect(screen.getByRole('radio', { name: 'Family B' })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getAllByRole('row')).toHaveLength(2); // header + 1 B row
  });

  it('uses a custom predicate when provided, in preference to filterField equality', async () => {
    const user = userEvent.setup();
    const opts = [
      { value: 'all', label: 'All' },
      { value: 'evens', label: 'Even-numbered', predicate: (r: Row) => Number(r.id.slice(1)) % 2 === 0 },
    ];
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={opts as any} />);
    await user.click(screen.getByRole('radio', { name: 'Even-numbered' }));
    expect(screen.getAllByRole('row')).toHaveLength(2); // header + A002 only
    expect(screen.getByText('alpha-two')).toBeInTheDocument();
  });

  it('marks the active pill with aria-checked="true" and data-active', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    const allPill = screen.getByRole('radio', { name: 'All' });
    expect(allPill).toHaveAttribute('aria-checked', 'true');
    expect(allPill).toHaveAttribute('data-active', 'true');
    expect(screen.getByRole('radio', { name: 'Family A' })).toHaveAttribute('data-active', 'false');
  });

  it('exposes the filter value via data-filter-value on each pill', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    expect(screen.getByRole('radio', { name: 'Family A' })).toHaveAttribute('data-filter-value', 'A');
  });
});

describe('FilterableTable — keyboard nav', () => {
  it('ArrowRight on focused pill activates the next pill (roving tabindex)', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    const all = screen.getByRole('radio', { name: 'All' });
    all.focus();
    await user.keyboard('{ArrowRight}');
    expect(screen.getByRole('radio', { name: 'Family A' })).toHaveAttribute('aria-checked', 'true');
  });

  it('ArrowLeft cycles backwards and wraps from first to last', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    screen.getByRole('radio', { name: 'All' }).focus();
    await user.keyboard('{ArrowLeft}');
    expect(screen.getByRole('radio', { name: 'Family B' })).toHaveAttribute('aria-checked', 'true');
  });

  it('Home jumps to the first pill, End to the last', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} initialFilter="A" />);
    screen.getByRole('radio', { name: 'Family A' }).focus();
    await user.keyboard('{End}');
    expect(screen.getByRole('radio', { name: 'Family B' })).toHaveAttribute('aria-checked', 'true');
    await user.keyboard('{Home}');
    expect(screen.getByRole('radio', { name: 'All' })).toHaveAttribute('aria-checked', 'true');
  });

  it('only the active pill has tabIndex 0; others are -1 (roving tabindex)', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} initialFilter="A" />);
    expect(screen.getByRole('radio', { name: 'All' })).toHaveAttribute('tabindex', '-1');
    expect(screen.getByRole('radio', { name: 'Family A' })).toHaveAttribute('tabindex', '0');
    expect(screen.getByRole('radio', { name: 'Family B' })).toHaveAttribute('tabindex', '-1');
  });
});

describe('FilterableTable — search', () => {
  it('renders a search input with the given placeholder', () => {
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} searchPlaceholder="Find a rule..." />);
    expect(screen.getByPlaceholderText('Find a rule...')).toBeInTheDocument();
  });

  it('narrows rows by case-insensitive substring of the searchable column', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    await user.type(screen.getByRole('searchbox'), 'a00');
    // case-insensitive: matches A001 and A002 (their ids start with A)
    expect(screen.getAllByRole('row')).toHaveLength(3); // header + 2
    expect(screen.queryByText('beta-one')).not.toBeInTheDocument();
  });

  it('composes with the pill filter (both must match)', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    await user.click(screen.getByRole('radio', { name: 'Family A' }));
    await user.type(screen.getByRole('searchbox'), '002');
    expect(screen.getAllByRole('row')).toHaveLength(2); // header + A002
    expect(screen.getByText('alpha-two')).toBeInTheDocument();
  });

  it('renders no search input when no column is searchable', () => {
    const cols = [
      { key: 'id' as const, header: 'ID' },              // not searchable
      { key: 'family' as const, header: 'Family' },
    ];
    render(<FilterableTable rows={ROWS} columns={cols as any} filterField="family" filterOptions={FILTERS} />);
    expect(screen.queryByRole('searchbox')).not.toBeInTheDocument();
  });
});

describe('FilterableTable — empty state and persistence', () => {
  it('renders an empty cell with colSpan=columns when no rows match', async () => {
    const user = userEvent.setup();
    render(<FilterableTable
      rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS}
      emptyMessage="No matches"
    />);
    await user.type(screen.getByRole('searchbox'), 'xyz-no-match');
    const empty = screen.getByText('No matches');
    expect(empty).toBeInTheDocument();
    expect(empty.closest('td')).toHaveAttribute('colspan', String(COLUMNS.length));
    expect(empty.closest('td')).toHaveAttribute('data-empty', 'true');
    expect(empty.closest('td')).toHaveAttribute('role', 'status');
  });

  it('uses a default empty message when none is supplied', async () => {
    const user = userEvent.setup();
    render(<FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />);
    await user.type(screen.getByRole('searchbox'), 'xyz-no-match');
    // a default message exists ("No matches" or similar) — assert by data-empty="true"
    expect(screen.getByRole('status')).toHaveAttribute('data-empty', 'true');
  });

  it('preserves the active filter when rows prop changes', async () => {
    const user = userEvent.setup();
    const { rerender } = render(
      <FilterableTable rows={ROWS} columns={COLUMNS} filterField="family" filterOptions={FILTERS} />
    );
    await user.click(screen.getByRole('radio', { name: 'Family A' }));
    rerender(
      <FilterableTable
        rows={[...ROWS, { id: 'A003', name: 'alpha-three', family: 'A' as const }]}
        columns={COLUMNS} filterField="family" filterOptions={FILTERS} />
    );
    expect(screen.getByRole('radio', { name: 'Family A' })).toHaveAttribute('aria-checked', 'true');
    expect(screen.getByText('alpha-three')).toBeInTheDocument();
  });
});
