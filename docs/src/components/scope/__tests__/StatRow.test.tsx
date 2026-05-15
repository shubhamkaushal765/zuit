import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import StatRow from '../StatRow';

describe('StatRow', () => {
  it('renders one list item per stat', () => {
    render(<StatRow stats={[
      { value: 52, label: 'Tier 1' },
      { value: 18, label: 'Tier 2' },
      { value: 9,  label: 'Tier 3' },
    ]} />);
    expect(screen.getAllByRole('listitem')).toHaveLength(3);
    expect(screen.getByText('52')).toBeInTheDocument();
    expect(screen.getByText('Tier 1')).toBeInTheDocument();
  });

  it('defaults aria-label to "Summary statistics" on the list', () => {
    render(<StatRow stats={[{ value: 1, label: 'x' }]} />);
    expect(screen.getByRole('list')).toHaveAttribute('aria-label', 'Summary statistics');
  });

  it('uses a caller-supplied ariaLabel', () => {
    render(<StatRow stats={[{ value: 1, label: 'x' }]} ariaLabel="CWE scope" />);
    expect(screen.getByRole('list')).toHaveAttribute('aria-label', 'CWE scope');
  });

  it('flows accent through as data-accent', () => {
    render(<StatRow stats={[
      { value: 1, label: 'a' },                              // default → neutral
      { value: 2, label: 'b', accent: 'info' },
      { value: 3, label: 'c', accent: 'warning' },
    ]} />);
    const items = screen.getAllByRole('listitem');
    expect(items[0]).toHaveAttribute('data-accent', 'neutral');
    expect(items[1]).toHaveAttribute('data-accent', 'info');
    expect(items[2]).toHaveAttribute('data-accent', 'warning');
  });

  it('renders an empty list when stats is empty (no crash)', () => {
    render(<StatRow stats={[]} />);
    expect(screen.getByRole('list')).toBeInTheDocument();
    expect(screen.queryAllByRole('listitem')).toHaveLength(0);
  });

  it('sets the hint as a title attribute when provided', () => {
    render(<StatRow stats={[{ value: 1, label: 'x', hint: 'why' }]} />);
    expect(screen.getAllByRole('listitem')[0]).toHaveAttribute('title', 'why');
  });

  it('omits the title attribute when hint is undefined', () => {
    render(<StatRow stats={[{ value: 1, label: 'x' }]} />);
    expect(screen.getAllByRole('listitem')[0]).not.toHaveAttribute('title');
  });
});
