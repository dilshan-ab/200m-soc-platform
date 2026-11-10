import { describe, expect, it } from 'vitest';
import { ago, titleCase, until } from './format';

describe('format helpers', () => {
  it('titleCases snake_case', () => expect(titleCase('in_progress')).toBe('In Progress'));
  it('handles missing dates', () => { expect(ago(null)).toBe('—'); expect(until(undefined)).toBe('—'); });
  it('reports overdue deadlines', () => expect(until(new Date(Date.now() - 3600_000).toISOString())).toMatch(/^overdue/));
  it('formats relative minutes', () => expect(ago(new Date(Date.now() - 5 * 60_000).toISOString())).toBe('5m ago'));
});
