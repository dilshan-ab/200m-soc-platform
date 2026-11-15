import { Bookmark, Plus, X } from 'lucide-react';
import { useState } from 'react';
import { useSearchParams } from 'react-router-dom';
import { useAuth } from '../lib/auth';
import { Button } from './Button';

type SavedView = { name: string; query: string };
const allowedFilters = {
  alerts: ['severity', 'status', 'q', 'category', 'source', 'host', 'client_id', 'unassigned_client', 'since'],
  cases: ['severity', 'status', 'q', 'mine'],
};

function loadViews(key: string): SavedView[] {
  try {
    const value: unknown = JSON.parse(localStorage.getItem(key) ?? '[]');
    if (!Array.isArray(value)) return [];
    return value.filter((entry): entry is SavedView => typeof entry?.name === 'string' && typeof entry?.query === 'string').slice(0, 20);
  } catch {
    return [];
  }
}

export function SavedViews({ area, onApply }: { area: keyof typeof allowedFilters; onApply: () => void }) {
  const { me } = useAuth();
  if (!me) return null;
  const storageKey = `200m:saved-views:${me.id}:${area}`;
  return <ViewPicker key={storageKey} storageKey={storageKey} area={area} onApply={onApply} />;
}

function ViewPicker({ storageKey, area, onApply }: {
  storageKey: string;
  area: keyof typeof allowedFilters;
  onApply: () => void;
}) {
  const [params, setParams] = useSearchParams();
  const [views, setViews] = useState(() => loadViews(storageKey));
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState('');
  const [error, setError] = useState('');
  const filters = (value: URLSearchParams) => {
    const result = new URLSearchParams();
    for (const key of allowedFilters[area]) {
      for (const item of value.getAll(key)) if (item) result.append(key, item);
    }
    return result;
  };
  const current = filters(params).toString();

  function persist(next: SavedView[]) {
    try {
      localStorage.setItem(storageKey, JSON.stringify(next));
      setViews(next);
      setError('');
      return true;
    } catch {
      setError('This browser could not save the view.');
      return false;
    }
  }

  function saveView() {
    const title = name.trim();
    if (!title || !current) return;
    const existing = views.findIndex((view) => view.name.toLowerCase() === title.toLowerCase());
    if (existing >= 0) {
      setError('A view already uses that name.');
      return;
    }
    if (persist([...views, { name: title, query: current }])) {
      setEditing(false);
      setName('');
    }
  }

  return (
    <section className="saved-views" aria-label="Saved views">
      <div className="saved-views-label"><Bookmark size={15} aria-hidden="true" /> Saved views</div>
      <div className="saved-views-items">
        {views.map((view, index) => (
          <span className="saved-view" key={view.name}>
            <button type="button" aria-pressed={view.query === current} onClick={() => {
              onApply();
              setParams(filters(new URLSearchParams(view.query)), { replace: true });
            }}>{view.name}</button>
            <button type="button" aria-label={`Remove view ${view.name}`} onClick={() => persist(views.filter((_, i) => i !== index))}><X size={13}/></button>
          </span>
        ))}
        {!views.length && !editing && <span className="saved-views-hint">Save a filter to return to it later.</span>}
      </div>
      {!editing && <Button type="button" variant="outline" disabled={!current || views.length >= 20} onClick={() => setEditing(true)}><Plus size={15} />Save current view</Button>}
      {editing && <form className="saved-views-form" onSubmit={(event) => { event.preventDefault(); saveView(); }}>
        <input autoFocus aria-label="View name" maxLength={36} placeholder="View name" value={name} onChange={(event) => { setName(event.target.value); setError(''); }} />
        <Button type="submit" disabled={!name.trim() || !current}>Save</Button>
        <Button type="button" variant="ghost" onClick={() => { setEditing(false); setError(''); }}>Cancel</Button>
      </form>}
      {error && <div role="alert" className="saved-views-error">{error}</div>}
    </section>
  );
}
