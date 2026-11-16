import * as echarts from 'echarts/core';
import { LineChart } from 'echarts/charts';
import { AriaComponent, DataZoomComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef } from 'react';
echarts.use([LineChart, DataZoomComponent, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer]);

export type Point = { day: string; alerts: number; critical: number; high: number };

export default function Trend({ dark, series }: { dark: boolean; series: Point[] }) {
  const ref = useRef<HTMLDivElement>(null);
  const instance = useRef<echarts.EChartsType | null>(null);
  useEffect(() => {
    const chart = echarts.init(ref.current!);
    instance.current = chart;
    const theme = getComputedStyle(document.documentElement);
    const txt = theme.getPropertyValue('--muted').trim();
    const border = theme.getPropertyValue('--border').trim();
    const surface = theme.getPropertyValue('--surface').trim();
    const text = theme.getPropertyValue('--text').trim();
    const motion = window.matchMedia('(prefers-reduced-motion: reduce)');
    chart.setOption({
      animation: !motion.matches, animationDuration: 750, animationEasing: 'cubicOut', animationDurationUpdate: 400,
      aria: { enabled: true, decal: { show: true } },
      tooltip: { trigger: 'axis', confine: true, backgroundColor: surface, borderColor: border, textStyle: { color: text }, axisPointer: { type: 'cross', snap: true, label: { backgroundColor: surface, color: text } } },
      legend: { bottom: 0, textStyle: { color: txt } },
      grid: { left: 40, right: 16, top: 16, bottom: 82 },
      dataZoom: [
        { type: 'inside', zoomOnMouseWheel: false, moveOnMouseWheel: false, preventDefaultMouseMove: false },
        { type: 'slider', bottom: 32, height: 18, borderColor: border, textStyle: { color: txt }, handleStyle: { color: surface, borderColor: txt }, fillerColor: dark ? '#63cde633' : '#0879a622' },
      ],
      xAxis: { type: 'category', boundaryGap: false, data: [], axisLabel: { color: txt }, axisLine: { lineStyle: { color: border } } },
      yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: border } }, axisLabel: { color: txt } },
      series: [
        { id: 'alerts', name: 'Total alerts', type: 'line', smooth: .25, symbolSize: 7, emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#43adff' : '#1465bb' }, areaStyle: { opacity: .16 } },
        { id: 'critical', name: 'Critical', type: 'line', smooth: .25, symbolSize: 7, emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#ff627a' : '#bb2448' }, areaStyle: { opacity: .12 } },
        { id: 'high', name: 'High', type: 'line', smooth: .25, symbolSize: 7, emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#ffc068' : '#945200' }, areaStyle: { opacity: .1 } },
      ],
    });
    const updateMotion = () => chart.setOption({ animation: !motion.matches });
    motion.addEventListener('change', updateMotion);
    const observer = new ResizeObserver(() => chart.resize());
    observer.observe(ref.current!);
    return () => { observer.disconnect(); motion.removeEventListener('change', updateMotion); instance.current = null; chart.dispose(); };
  }, [dark]);
  // Merge live values into the existing instance to preserve zoom and legend selections.
  useEffect(() => {
    instance.current?.setOption({
      xAxis: { data: series.map((s) => s.day.length > 5 ? s.day.slice(5) : s.day) },
      series: ['alerts', 'critical', 'high'].map((key) => ({ id: key, showSymbol: series.length < 2, data: series.map((s) => s[key as 'alerts' | 'critical' | 'high']) })),
    });
  }, [series, dark]);
  return <div className="trend-explorer">
    <div className="trend-controls"><span>Hover for values · drag the range to zoom</span><button type="button" className="btn small" onClick={() => instance.current?.dispatchAction({ type: 'dataZoom', start: 50, end: 100 })}>Recent half</button><button type="button" className="btn small" onClick={() => instance.current?.dispatchAction({ type: 'dataZoom', start: 0, end: 100 })}>Reset zoom</button></div>
    <div ref={ref} className="chart" role="img" aria-label="Alert activity by severity. Use the range controls to zoom and the legend to toggle series." />
  </div>;
}
