import { useEffect, useRef, useState } from 'react';
import type { GeometryCollection, Topology } from 'topojson-specification';

export function LoginGlobe({ paused = false }: { paused?: boolean }) {
  const landPath = useRef<SVGPathElement>(null);
  const gridPath = useRef<SVGPathElement>(null);
  const rotation = useRef(0);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let frame = 0;
    let run = 0;

    const start = async (currentRun: number) => {
      const [atlas, { feature }, { geoOrthographic, geoGraticule10, geoPath }] = await Promise.all([
        import('world-atlas/land-110m.json'), import('topojson-client'), import('d3-geo'),
      ]);
      const landElement = landPath.current;
      const gridElement = gridPath.current;
      if (currentRun !== run || !landElement || !gridElement) return;

      const topology = atlas.default as unknown as Topology<{ land: GeometryCollection }>;
      const land = feature(topology, topology.objects.land);
      const grid = geoGraticule10();
      const projection = geoOrthographic().translate([300, 300]).scale(214).precision(1);
      const path = geoPath(projection);
      const startedAt = performance.now();
      let lastDraw = -Infinity;
      let lastRotation = startedAt;

      const draw = (now: number) => {
        if (now - lastDraw >= 1000 / 30) {
          rotation.current = (rotation.current + (now - lastRotation) * 0.006) % 360;
          lastRotation = now;
          projection.rotate([-20 - rotation.current, -18, 0]);
          landElement.setAttribute('d', path(land) ?? '');
          gridElement.setAttribute('d', path(grid) ?? '');
          lastDraw = now;
        }
        frame = requestAnimationFrame(draw);
      };
      draw(startedAt);
      setReady(true);
    };

    const syncMotion = () => {
      const currentRun = ++run;
      cancelAnimationFrame(frame);
      if (motion.matches) setReady(false);
      else if (!paused) void start(currentRun).catch(() => {
        if (currentRun === run) setReady(false);
      });
    };
    syncMotion();
    motion.addEventListener('change', syncMotion);
    return () => {
      run++;
      cancelAnimationFrame(frame);
      motion.removeEventListener('change', syncMotion);
    };
  }, [paused]);

  return (
    <div className="login-globe">
    <svg className="login-globe-svg" viewBox="0 0 600 600" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <defs>
        <radialGradient id="login-globe-ocean" cx="37%" cy="25%" r="76%">
          <stop stopColor="#154b90" />
          <stop offset=".55" stopColor="#092b61" />
          <stop offset=".88" stopColor="#061838" />
          <stop offset="1" stopColor="#1162a9" />
        </radialGradient>
        <linearGradient id="login-globe-rim" x2=".72" y2="1">
          <stop stopColor="#5beaff" />
          <stop offset=".5" stopColor="#348dff" />
          <stop offset="1" stopColor="#0b3c8a" />
        </linearGradient>
        <pattern id="login-globe-dots" width="3.4" height="3.4" patternUnits="userSpaceOnUse">
          <rect width="3.4" height="3.4" fill="#1177dc" opacity=".26" />
          <circle cx="1.7" cy="1.7" r="1" fill="#41bdff" />
        </pattern>
      </defs>
      {!ready && <image href="/login-globe.svg" width="600" height="600" />}
      <g visibility={ready ? 'visible' : 'hidden'}>
        <circle cx="300" cy="300" r="214" fill="url(#login-globe-ocean)" stroke="url(#login-globe-rim)" strokeWidth="2" />
        <path ref={gridPath} fill="none" stroke="#439cff" strokeWidth=".65" opacity=".3" />
        <path ref={landPath} fill="url(#login-globe-dots)" />
        {/* Each ring is a group pivoting around the globe's center; its satellite dots are
            nested inside so they travel around the ellipse with it instead of sitting static. */}
        <g className="login-globe-orbit login-globe-orbit-a" fill="none" stroke="#439cff" opacity=".62">
          <ellipse cx="300" cy="300" rx="273" ry="110" />
          <circle cx="43" cy="262" r="3" fill="#b8f7ff" stroke="#27b9ff" strokeWidth="2" />
          <circle cx="569" cy="281" r="3" fill="#b8f7ff" stroke="#27b9ff" strokeWidth="2" />
        </g>
        <g className="login-globe-orbit login-globe-orbit-b" fill="none" stroke="#439cff" opacity=".62">
          <ellipse cx="300" cy="300" rx="263" ry="153" />
          <circle cx="210" cy="444" r="3" fill="#b8f7ff" stroke="#27b9ff" strokeWidth="2" />
          <circle cx="432" cy="168" r="3" fill="#b8f7ff" stroke="#27b9ff" strokeWidth="2" />
        </g>
        <g className="login-globe-orbit login-globe-orbit-c" fill="none" stroke="#439cff" opacity=".62">
          <ellipse cx="300" cy="300" rx="250" ry="143" strokeDasharray="2 6" />
          <circle cx="425" cy="424" r="3" fill="#b8f7ff" stroke="#27b9ff" strokeWidth="2" />
        </g>
      </g>
    </svg>
    </div>
  );
}
