import type { KeyboardEvent } from 'react';

/** Row navigation stays within a table and leaves nested inputs/links alone. */
export function tableKeyboard(event: KeyboardEvent<HTMLElement>) {
  const target = event.target as HTMLElement;
  if (event.altKey || event.ctrlKey || event.metaKey || event.shiftKey || document.querySelector('[role=dialog]')) return;
  const row = target.closest<HTMLTableRowElement>('tbody tr[tabindex]');
  if (!row || target !== row) return;
  const table = row.closest('table');
  const rows = [...(table?.querySelectorAll<HTMLTableRowElement>('tbody tr[tabindex]') ?? [])];
  const index = rows.indexOf(row);
  let next = index;
  if (event.key === 'ArrowDown' || event.key === 'j') next = Math.min(index + 1, rows.length - 1);
  else if (event.key === 'ArrowUp' || event.key === 'k') next = Math.max(index - 1, 0);
  else if (event.key === 'Home') next = 0;
  else if (event.key === 'End') next = rows.length - 1;
  else if (event.key === ' ') { event.preventDefault(); row.click(); return; }
  else return;
  event.preventDefault();
  event.stopPropagation();
  rows[next]?.focus({ preventScroll: true });
  rows[next]?.scrollIntoView({ block: 'nearest', inline: 'nearest' });
}
