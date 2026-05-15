import { describe, it, expect } from 'vitest';
import { render, screen, within } from '@testing-library/react';
import LangDots from '../LangDots';

describe('LangDots', () => {
  it('renders three dots in Rs/Py/JS order', () => {
    const { container } = render(<LangDots langs={{ rs: true, py: true, js: true }} />);
    const dots = container.querySelectorAll('[data-lang]');
    expect(dots).toHaveLength(3);
    expect(dots[0]).toHaveAttribute('data-lang', 'rs');
    expect(dots[1]).toHaveAttribute('data-lang', 'py');
    expect(dots[2]).toHaveAttribute('data-lang', 'js');
    expect(dots[0]).toHaveTextContent('Rs');
    expect(dots[1]).toHaveTextContent('Py');
    expect(dots[2]).toHaveTextContent('JS');
  });

  it('flags an unset language as data-dim="true"', () => {
    const { container } = render(<LangDots langs={{ rs: true }} />);
    const dots = container.querySelectorAll('[data-lang]');
    expect(dots[0]).toHaveAttribute('data-dim', 'false');   // rs supported
    expect(dots[1]).toHaveAttribute('data-dim', 'true');    // py missing → dim
    expect(dots[2]).toHaveAttribute('data-dim', 'true');    // js missing → dim
  });

  it('treats explicit false the same as missing', () => {
    const { container } = render(<LangDots langs={{ rs: false, py: true, js: false }} />);
    const dots = container.querySelectorAll('[data-lang]');
    expect(dots[0]).toHaveAttribute('data-dim', 'true');
    expect(dots[1]).toHaveAttribute('data-dim', 'false');
    expect(dots[2]).toHaveAttribute('data-dim', 'true');
  });

  it('sets human-readable title and supported aria-label on each dot', () => {
    render(<LangDots langs={{ rs: true, py: true, js: true }} />);
    expect(screen.getByLabelText('Rust supported')).toHaveAttribute('title', 'Rust');
    expect(screen.getByLabelText('Python supported')).toHaveAttribute('title', 'Python');
    expect(screen.getByLabelText('JavaScript/TypeScript supported')).toHaveAttribute('title', 'JavaScript/TypeScript');
  });

  it('flips the aria-label when a language is not supported', () => {
    render(<LangDots langs={{}} />);
    expect(screen.getByLabelText('Rust not supported')).toBeInTheDocument();
    expect(screen.getByLabelText('Python not supported')).toBeInTheDocument();
    expect(screen.getByLabelText('JavaScript/TypeScript not supported')).toBeInTheDocument();
  });

  it('wraps the dots in a group with an accessible label', () => {
    render(<LangDots langs={{ rs: true }} />);
    const group = screen.getByRole('group', { name: 'Language coverage' });
    expect(group).toBeInTheDocument();
    expect(within(group).getAllByText(/^(Rs|Py|JS)$/)).toHaveLength(3);
  });

  it('flows the size prop through as data-size on each dot', () => {
    const { container } = render(<LangDots langs={{ rs: true }} size="md" />);
    const dots = container.querySelectorAll('[data-lang]');
    dots.forEach(d => expect(d).toHaveAttribute('data-size', 'md'));
  });

  it('defaults data-size to "sm"', () => {
    const { container } = render(<LangDots langs={{ rs: true }} />);
    expect(container.querySelectorAll('[data-lang]')[0]).toHaveAttribute('data-size', 'sm');
  });
});
