export function CircuitLogo({ className, strokeWidth = 4 }: { className: string; strokeWidth?: number }) {
  return (
    <svg className={className} viewBox="0 0 560 190" aria-hidden="true">
      <g
        fill="none"
        stroke="currentColor"
        strokeWidth={strokeWidth}
        strokeLinecap="round"
        strokeLinejoin="round"
      >
        <path
          className="circuit-line"
          pathLength="1"
          d="M20 58C20 30 44 16 66 16C90 16 110 32 110 56C110 84 82 104 22 150H112"
        />
        <ellipse className="circuit-line circuit-delay-one" pathLength="1" cx="180" cy="95" rx="46" ry="63" />
        <ellipse className="circuit-line circuit-delay-two" pathLength="1" cx="300" cy="95" rx="46" ry="63" />
        <path
          className="circuit-line circuit-delay-three"
          pathLength="1"
          d="M368 150V20L410 90L452 20V150"
        />
      </g>
      <path
        className="circuit-line circuit-delay-three"
        pathLength="1"
        fill="none"
        stroke="currentColor"
        strokeWidth={Math.max(2, strokeWidth * 0.4)}
        strokeLinecap="round"
        d="M466 26C480 10 500 8 510 18"
      />
      <g className="circuit-nodes">
        <circle cx="510" cy="18" r="8" fill="var(--bg)" stroke="currentColor" strokeWidth="3" />
        <circle cx="510" cy="18" r="3.6" fill="#34c3eb" />
      </g>
    </svg>
  );
}
