import { useEffect, useMemo, useRef } from 'react';

type Orb = {
  x: number;
  y: number;
  r: number;
  vx: number;
  vy: number;
  a: number;
};

function getPrefersReducedMotion(): boolean {
  try {
    return window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  } catch {
    return false;
  }
}

export default function AmbientAura() {
  const canvasRef = useRef<HTMLCanvasElement | null>(null);

  const orbs = useMemo<Orb[]>(() => {
    const count = 5;
    return Array.from({ length: count }, () => {
      const r = 140 + Math.random() * 220;
      const speed = 0.008 + Math.random() * 0.018;
      const a = 0.06 + Math.random() * 0.09;
      const dir = Math.random() * Math.PI * 2;
      return {
        x: Math.random(),
        y: Math.random(),
        r,
        vx: Math.cos(dir) * speed,
        vy: Math.sin(dir) * speed,
        a,
      };
    });
  }, []);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return;

    const reduced = getPrefersReducedMotion();
    if (reduced) return;

    const ctx = canvas.getContext('2d');
    if (!ctx) return;

    let raf = 0;
    let last = performance.now();
    let running = true;

    const resize = () => {
      const dpr = Math.min(window.devicePixelRatio || 1, 2);
      const { innerWidth: w, innerHeight: h } = window;
      canvas.width = Math.floor(w * dpr);
      canvas.height = Math.floor(h * dpr);
      canvas.style.width = `${w}px`;
      canvas.style.height = `${h}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    };

    const onVisibility = () => {
      running = document.visibilityState === 'visible';
      if (running) {
        last = performance.now();
        raf = requestAnimationFrame(tick);
      } else {
        cancelAnimationFrame(raf);
      }
    };

    const tick = (now: number) => {
      if (!running) return;

      const dt = Math.min((now - last) / 1000, 0.05);
      last = now;

      const w = window.innerWidth;
      const h = window.innerHeight;

      ctx.clearRect(0, 0, w, h);

      for (const orb of orbs) {
        orb.x += orb.vx * dt;
        orb.y += orb.vy * dt;

        if (orb.x < -0.2) orb.x = 1.2;
        if (orb.x > 1.2) orb.x = -0.2;
        if (orb.y < -0.2) orb.y = 1.2;
        if (orb.y > 1.2) orb.y = -0.2;

        const cx = orb.x * w;
        const cy = orb.y * h;

        const g = ctx.createRadialGradient(cx, cy, 0, cx, cy, orb.r);
        g.addColorStop(0, `rgba(255, 10, 42, ${orb.a})`);
        g.addColorStop(0.35, `rgba(196, 0, 34, ${orb.a * 0.6})`);
        g.addColorStop(1, 'rgba(0, 0, 0, 0)');

        ctx.fillStyle = g;
        ctx.beginPath();
        ctx.arc(cx, cy, orb.r, 0, Math.PI * 2);
        ctx.fill();
      }

      raf = requestAnimationFrame(tick);
    };

    resize();
    raf = requestAnimationFrame(tick);

    window.addEventListener('resize', resize);
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener('resize', resize);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [orbs]);

  return (
    <div className="fixed inset-0 z-0 pointer-events-none">
      <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,#110000_0%,#000000_70%)]" />
      <canvas ref={canvasRef} className="absolute inset-0 opacity-70" />
      <div className="absolute inset-0 bg-[linear-gradient(to_bottom,rgba(0,0,0,0.1),rgba(0,0,0,0.6))]" />
    </div>
  );
}
