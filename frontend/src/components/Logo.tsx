/** 200M brand: shield mark + circuit-drawn "200M" word. Colours come from CSS tokens (blue). */
export function BrandMark({ className = 'brand-mark' }: { className?: string }) {
  return (
    <svg className={className} viewBox="0 0 48 48" fill="none" aria-hidden="true">
      <rect x="1" y="1" width="46" height="46" rx="14" className="brand-tile" />
      <path d="M24 7 36 13v11c0 8-12 16-12 16S12 32 12 24V13Z" className="brand-shield" strokeWidth="1.8" strokeLinejoin="round" />
      <path d="m24 15-7 14 7-4 7 4Z" className="brand-beacon" strokeLinejoin="round" />
      <path d="M8 32c-5-2 1-11 13-17S44 8 42 14M40 20c-3 5-12 11-21 14" className="brand-orbit" strokeWidth="1.6" strokeLinecap="round" />
      <circle cx="41" cy="16" r="2.5" className="brand-satellite" />
    </svg>
  );
}

export function Brand({ subtitle = 'SOC' }: { subtitle?: string }) {
  return (
    <div className="brand brand-circuit">
      <div style={{ width: 120 }}><CircuitWord animated={false} label="200M" /></div>
      <span className="brand-pill">{subtitle}</span>
    </div>
  );
}

export function CircuitWord({ animated = true, label = '200M' }: { animated?: boolean; label?: string }) {
  return (
    <svg className={`circuit-word${animated ? '' : ' circuit-static'}`} viewBox="0 0 540 220" role="img" aria-label={label}>
      <g fill="none" stroke="currentColor" strokeWidth="4" strokeLinecap="round" strokeLinejoin="round">
        <path className="circuit-line" pathLength={1} d="M28 88C28 32 111 26 120 82C126 113 87 141 47 174H145M47 88C47 54 95 52 99 82C103 101 72 125 28 166C18 177 23 190 39 190H151" />
        <path className="circuit-line circuit-delay-one" pathLength={1} d="M190 190C144 190 124 155 130 110C136 61 173 26 217 37M208 57C177 48 153 80 150 112C145 146 162 167 185 167C214 167 232 142 235 110" />
        <path className="circuit-line circuit-delay-two" pathLength={1} d="M183 190C223 191 257 168 258 113C260 72 291 50 318 62C348 77 350 113 337 143C326 172 306 181 281 170M224 108C220 70 255 30 295 31H313M245 170C276 206 325 197 350 162C377 126 373 73 343 48" />
        <path className="circuit-line circuit-delay-three" pathLength={1} d="M341 33C358 31 371 37 382 53L417 105L460 44Q468 30 487 33Q502 34 502 49V182Q502 191 491 191Q479 191 479 180V81L430 147Q417 159 405 143L366 89" />
      </g>
      <g className="circuit-nodes" strokeWidth="2">
        <circle cx="28" cy="88" r="6" /><circle cx="183" cy="190" r="5" /><circle cx="235" cy="110" r="5" />
        <circle cx="341" cy="33" r="6" /><circle cx="502" cy="160" r="5" />
      </g>
    </svg>
  );
}

/** Full-screen landing animation. Skippable; hidden under prefers-reduced-motion (CSS). */
export function Intro({ onDone }: { onDone: () => void }) {
  return (
    <div className="company-intro" role="dialog" aria-label="Welcome" onAnimationEnd={(e) => { if (e.animationName === 'intro-depart') onDone(); }}>
      <div className="intro-coordinate">SOC · 6.9271° N · 79.8612° E</div>
      <div className="intro-matter"><div className="intro-halo" /><CircuitWord /></div>
      <div className="intro-caption">SECURITY OPERATIONS CENTER</div>
      <button className="intro-skip" onClick={onDone}>Skip intro <span>→</span></button>
      <div className="intro-track" />
    </div>
  );
}
