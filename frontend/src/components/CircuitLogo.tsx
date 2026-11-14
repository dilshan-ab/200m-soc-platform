export function CircuitLogo({ className, strokeWidth = 4 }: { className: string; strokeWidth?: number }) {
  return (
    <svg className={className} viewBox="0 0 540 220" aria-hidden="true">
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
          d="M28 88C28 32 111 26 120 82C126 113 87 141 47 174H145M47 88C47 54 95 52 99 82C103 101 72 125 28 166C18 177 23 190 39 190H151"
        />
        <path
          className="circuit-line circuit-delay-one"
          pathLength="1"
          d="M190 190C144 190 124 155 130 110C136 61 173 26 217 37M208 57C177 48 153 80 150 112C145 146 162 167 185 167C214 167 232 142 235 110"
        />
        <path
          className="circuit-line circuit-delay-two"
          pathLength="1"
          d="M183 190C223 191 257 168 258 113C260 72 291 50 318 62C348 77 350 113 337 143C326 172 306 181 281 170M224 108C220 70 255 30 295 31H313M245 170C276 206 325 197 350 162C377 126 373 73 343 48"
        />
        <path
          className="circuit-line circuit-delay-three"
          pathLength="1"
          d="M341 33C358 31 371 37 382 53L417 105L460 44Q468 30 487 33Q502 34 502 49V182Q502 191 491 191Q479 191 479 180V81L430 147Q417 159 405 143L366 89"
        />
      </g>
      <g className="circuit-nodes" fill="currentColor" stroke="var(--bg)" strokeWidth="2">
        <circle cx="28" cy="88" r="6" />
        <circle cx="183" cy="190" r="5" />
        <circle cx="235" cy="110" r="5" />
        <circle cx="341" cy="33" r="6" />
        <circle cx="502" cy="160" r="5" />
      </g>
    </svg>
  );
}
