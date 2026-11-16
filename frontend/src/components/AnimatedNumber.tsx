import { useEffect, useRef, useState } from 'react';

const number = new Intl.NumberFormat(undefined, { maximumFractionDigits: 1 });

export function AnimatedNumber({ value, suffix = '' }: { value: number | null; suffix?: string }) {
  const [display, setDisplay] = useState(0);
  const current = useRef(0);
  useEffect(() => {
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    let frame = 0;
    const target = value ?? 0;
    const start = current.current;
    const startedAt = performance.now();
    const finish = () => { cancelAnimationFrame(frame); current.current = target; setDisplay(target); };
    const draw = (now: number) => {
      const progress = Math.min(1, (now - startedAt) / 650);
      current.current = start + (target - start) * (1 - (1 - progress) ** 3);
      setDisplay(current.current);
      if (progress < 1) frame = requestAnimationFrame(draw);
    };
    if (motion.matches) finish(); else frame = requestAnimationFrame(draw);
    const changed = () => { if (motion.matches) finish(); };
    motion.addEventListener('change', changed);
    return () => { cancelAnimationFrame(frame); motion.removeEventListener('change', changed); };
  }, [value]);
  if (value === null) return <>—</>;
  return <span aria-label={`${number.format(value)}${suffix}`}><span aria-hidden="true">{number.format(Number.isInteger(value) ? Math.round(display) : display)}{suffix}</span></span>;
}
