import { cleanup, fireEvent, render, screen, within } from '@testing-library/react';
import { afterEach, expect, it } from 'vitest';
import { ThreatCategories } from './ThreatCategories';

afterEach(cleanup);

it('keeps the single-category distribution as a circular ring', () => {
  const { container } = render(<ThreatCategories categories={[{ name: 'security', count: 337 }]} />);
  expect(container.querySelector('circle.category-arc')?.getAttribute('stroke-dasharray')).toBe('100 0');
  expect(screen.getByRole('button', { name: 'Security: 337 alerts, 100%' })).toBeTruthy();
  expect(container.querySelector('.category-center strong')?.textContent).toBe('337');
});

it('selects categories, previews them on focus, and resets the selection', () => {
  const { container } = render(<ThreatCategories categories={[{ name: 'security', count: 8 }, { name: 'network', count: 2 }]} />);
  const network = screen.getByRole('button', { name: 'Network: 2 alerts, 20%' });
  fireEvent.focus(network);
  expect(container.querySelector('.category-center strong')?.textContent).toBe('2');
  fireEvent.click(network);
  fireEvent.blur(network);
  expect(network.getAttribute('aria-pressed')).toBe('true');
  expect(container.querySelector('.category-center span')?.textContent).toBe('Network');
  fireEvent.click(screen.getByRole('button', { name: 'Show all categories' }));
  expect(network.getAttribute('aria-pressed')).toBe('false');
  expect(container.querySelector('.category-center strong')?.textContent).toBe('10');
});

it('preserves every alert when smaller categories are grouped', () => {
  const { container } = render(<ThreatCategories categories={[10, 8, 6, 4, 2, 1].map((count, index) => ({ name: `type ${index}`, count }))} />);
  const legend = screen.getByRole('list', { name: 'Alert categories by share' });
  expect(within(legend).getAllByRole('button')).toHaveLength(5);
  expect(within(legend).getByRole('button', { name: /Other categories: 3 alerts/ })).toBeTruthy();
  expect(container.querySelector('.category-center strong')?.textContent).toBe('31');
});

it('handles empty data and a selected category disappearing after refresh', () => {
  const { rerender, container } = render(<ThreatCategories categories={[{ name: 'security', count: 3 }]} />);
  fireEvent.click(screen.getByRole('button', { name: /Security:/ }));
  rerender(<ThreatCategories categories={[{ name: 'network', count: 4 }]} />);
  expect(container.querySelector('.category-center strong')?.textContent).toBe('4');
  expect(screen.queryByRole('button', { name: 'Show all categories' })).toBeNull();
  rerender(<ThreatCategories categories={[{ name: 'network', count: 0 }]} />);
  expect(screen.getByText('No alerts to categorize in this period.')).toBeTruthy();
  expect(container.querySelector('svg .category-arc')).toBeNull();
});
