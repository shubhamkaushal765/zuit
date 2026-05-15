import { describe, it, expect } from 'vitest';
import { render, screen } from '@testing-library/react';
import CategoryBadge from '../CategoryBadge';

describe('CategoryBadge', () => {
  it('renders the label text', () => {
    render(<CategoryBadge label="Security" />);
    expect(screen.getByText('Security')).toBeInTheDocument();
  });

  it('defaults to data-tone="neutral"', () => {
    render(<CategoryBadge label="Other" />);
    expect(screen.getByText('Other')).toHaveAttribute('data-tone', 'neutral');
  });

  it('reflects an explicit tone via data-tone', () => {
    render(<CategoryBadge label="Risk" tone="warning" />);
    expect(screen.getByText('Risk')).toHaveAttribute('data-tone', 'warning');
  });

  it('sets data-monospace="true" when monospace prop is set', () => {
    render(<CategoryBadge label="MAINT001" monospace />);
    expect(screen.getByText('MAINT001')).toHaveAttribute('data-monospace', 'true');
  });

  it('forwards a custom className alongside the badge class', () => {
    const { container } = render(<CategoryBadge label="X" className="extra" />);
    const span = container.querySelector('span');
    expect(span?.className).toContain('extra');
    expect(span?.className).toContain('badge'); // CSS module's `badge` class
  });
});
