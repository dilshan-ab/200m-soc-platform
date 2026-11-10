import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { AriaComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef } from 'react';
echarts.use([LineChart, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer]);

export type Point = { day: string; alerts: number; critical: number; high: number };

export default function Trend({ dark, series }: { dark: boolean; series: Point[] }) {
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const chart = echarts.init(ref.current!);
    const theme = getComputedStyle(document.documentElement);
    const txt = theme.getPropertyValue('--muted').trim();
    const border = theme.getPropertyValue('--border').trim();
    const surface = theme.getPropertyValue('--surface').trim();
    const text = theme.getPropertyValue('--text').trim();
    chart.setOption({
      animation: !window.matchMedia('(prefers-reduced-motion: reduce)').matches,
      aria: { enabled: true, decal: { show: true } },
      tooltip: { trigger: 'axis', backgroundColor: surface, borderColor: border, textStyle: { color: text } },
      legend: { bottom: 0, textStyle: { color: txt } },
      grid: { left: 35, right: 12, top: 15, bottom: 58 },
      xAxis: { type: 'category', data: series.map((s) => s.day.length > 5 ? s.day.slice(5) : s.day), axisLabel: { color: txt }, axisLine: { lineStyle: { color: border } } },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: border } }, axisLabel: { color: txt } },
      series: [
        { name: 'Total alerts', type: 'line', smooth: .25, showSymbol: series.length < 2, data: series.map((s) => s.alerts), itemStyle: { color: dark ? '#43adff' : '#1465bb' }, areaStyle: { opacity: .16 } },
        { name: 'Critical', type: 'line', smooth: .25, showSymbol: series.length < 2, data: series.map((s) => s.critical), itemStyle: { color: dark ? '#ff627a' : '#bb2448' }, areaStyle: { opacity: .12 } },
        { name: 'High', type: 'line', smooth: .25, showSymbol: series.length < 2, data: series.map((s) => s.high), itemStyle: { color: dark ? '#ffc068' : '#945200' }, areaStyle: { opacity: .1 } },
      ],
    });
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(ref.current!);
    return () => { observer.disconnect(); chart.dispose(); };
  }, [dark, series]);
  return <div ref={ref} className="chart" role="img" aria-label="Alert activity by severity over the selected period" />;
}
