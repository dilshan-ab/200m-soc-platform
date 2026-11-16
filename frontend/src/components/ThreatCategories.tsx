import { PieChart } from 'lucide-react';
import { useState } from 'react';
import { titleCase } from '../lib/format';

const COLORS = ['#ff4665', '#ffa035', '#328eff', '#8c63f5', '#7788a5'];
const number = new Intl.NumberFormat();
const percent = new Intl.NumberFormat(undefined, { style: 'percent', maximumFractionDigits: 1 });

export function ThreatCategories({ categories }: { categories: { name: string; count: number }[] }) {
  const [selected, setSelected] = useState<string | null>(null);
  const [hovered, setHovered] = useState<string | null>(null);
  const ranked = categories.filter(({ count }) => count > 0).sort((a, b) => b.count - a.count);
  const total = ranked.reduce((sum, item) => sum + item.count, 0);
  const remainder = ranked.slice(4).reduce((sum, item) => sum + item.count, 0);
  const slices = ranked.slice(0, 4).map(({ name, count }, index) => ({
    key: `category:${name}`, label: titleCase(name || 'Uncategorized'), count, color: COLORS[index],
  }));
  if (remainder) slices.push({ key: 'remainder', label: 'Other categories', count: remainder, color: COLORS[4] });
  const selectedSlice = slices.find(({ key }) => key === selected);
  const active = slices.find(({ key }) => key === hovered) ?? selectedSlice;
  let offset = 0;

  return <section className="panel threat-categories">
    <div className="panel-title"><div><h2><PieChart size={18} aria-hidden="true" /> Top Threat Categories</h2><p>Hover or select a category to explore its share</p></div></div>
    {!total ? <p className="empty">No alerts to categorize in this period.</p> : <>
      <div className="category-explorer">
        <div className="category-ring" onPointerLeave={() => setHovered(null)}>
          <svg viewBox="0 0 160 160" aria-hidden="true">
            <circle cx="80" cy="80" r="60" className="category-track" />
            <g transform="rotate(-90 80 80)">{slices.map((slice) => {
              const share = slice.count / total * 100;
              const start = offset;
              offset += share;
              return <circle key={slice.key} cx="80" cy="80" r="60" pathLength="100"
                className="category-arc" data-active={active?.key === slice.key} data-muted={!!active && active.key !== slice.key}
                stroke={slice.color} strokeDasharray={`${share} ${100 - share}`} strokeDashoffset={-start}
                onPointerEnter={() => setHovered(slice.key)} onClick={() => setSelected(selected === slice.key ? null : slice.key)}>
                <title>{slice.label}: {number.format(slice.count)} alerts ({percent.format(slice.count / total)})</title>
              </circle>;
            })}</g>
          </svg>
          <div className="category-center"><strong>{number.format(active?.count ?? total)}</strong><span>{active?.label ?? 'Alerts'}</span>{active && <small>{percent.format(active.count / total)}</small>}</div>
        </div>
        <ul className="category-choices" aria-label="Alert categories by share">{slices.map((slice) => <li key={slice.key}>
          <button type="button" aria-pressed={selected === slice.key} aria-label={`${slice.label}: ${number.format(slice.count)} alerts, ${percent.format(slice.count / total)}`}
            data-highlighted={active?.key === slice.key} onMouseEnter={() => setHovered(slice.key)} onMouseLeave={() => setHovered(null)}
            onFocus={() => setHovered(slice.key)} onBlur={() => setHovered(null)} onClick={() => setSelected(selected === slice.key ? null : slice.key)}>
            <i style={{ background: slice.color }} aria-hidden="true" /><span>{slice.label}<small>{number.format(slice.count)} alerts</small></span><strong>{percent.format(slice.count / total)}</strong>
          </button>
        </li>)}</ul>
      </div>
      {selectedSlice && <button type="button" className="btn small category-reset" onClick={() => { setSelected(null); setHovered(null); }}>Show all categories</button>}
    </>}
  </section>;
}
