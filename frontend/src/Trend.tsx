import * as echarts from 'echarts/core';
import { BarChart, LineChart } from 'echarts/charts';
import { AriaComponent, DataZoomComponent, GridComponent, LegendComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef, useState } from 'react';
echarts.use([BarChart, LineChart, DataZoomComponent, GridComponent, TooltipComponent, LegendComponent, AriaComponent, CanvasRenderer]);

export type Point = { day: string; since?: string; until?: string; alerts: number; critical: number; high: number };

export default function Trend({ dark, series, onInspect }: { dark: boolean; series: Point[]; onInspect?: (point: Point, severity?: string) => void }) {
  const [bucket, setBucket] = useState('');
  const [severity, setSeverity] = useState('');
  const [focus, setFocus] = useState(false);
  const point = series.find((p) => p.since === bucket && p.until);
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
      tooltip: { trigger: 'axis', confine: true, backgroundColor: surface, borderColor: border, textStyle: { color: text }, axisPointer: { type: 'shadow', shadowStyle: { color: dark ? '#43adff20' : '#1465bb18' } } },
      legend: { bottom: 0, textStyle: { color: txt } },
      grid: { left: 40, right: 44, top: 28, bottom: 82 },
      dataZoom: [
        { type: 'inside', zoomOnMouseWheel: false, moveOnMouseWheel: false, preventDefaultMouseMove: false },
        { type: 'slider', bottom: 32, height: 18, borderColor: border, textStyle: { color: txt }, handleStyle: { color: surface, borderColor: txt }, fillerColor: dark ? '#63cde633' : '#0879a622' },
      ],
      xAxis: { type: 'category', boundaryGap: true, data: [], axisLabel: { color: txt, hideOverlap: true, formatter: (label: string) => label.length > 5 ? label.slice(5) : label }, axisLine: { lineStyle: { color: border } } },
      // Critical and high counts are tiny next to the total, so they get their own right-hand scale and are drawn as bars.
      yAxis: [
        { type: 'value', name: 'All', minInterval: 1, nameTextStyle: { color: txt }, splitLine: { lineStyle: { color: border } }, axisLabel: { color: txt } },
        { type: 'value', name: 'Critical + high', minInterval: 1, nameTextStyle: { color: txt }, splitLine: { show: false }, axisLabel: { color: txt } },
      ],
      series: [
        { id: 'alerts', name: 'Total alerts', type: 'line', z: 2, smooth: false, symbolSize: 7, emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#43adff' : '#1465bb' }, areaStyle: { opacity: .16 } },
        { id: 'critical', name: 'Critical', type: 'bar', z: 3, yAxisIndex: 1, stack: 'severity', barMaxWidth: 18, cursor: 'pointer', emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#ff627a' : '#bb2448' } },
        { id: 'high', name: 'High', type: 'bar', z: 3, yAxisIndex: 1, stack: 'severity', barMaxWidth: 18, cursor: 'pointer', emphasis: { focus: 'series' }, itemStyle: { color: dark ? '#ffc068' : '#945200', borderRadius: [3, 3, 0, 0] } },
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
      xAxis: { data: series.map((s) => s.day) },
      series: [
        { id: 'alerts', cursor: onInspect ? 'pointer' : 'default', showSymbol: !!onInspect || series.length < 2, data: series.map((s) => s.alerts) },
        { id: 'critical', data: series.map((s) => s.critical) },
        { id: 'high', data: series.map((s) => s.high) },
      ],
    });
  }, [series, dark, onInspect]);
  // Focus mode hides the total line so the critical and high bars fill the chart.
  useEffect(() => {
    const chart = instance.current;
    if (!chart) return;
    chart.dispatchAction({ type: focus ? 'legendUnSelect' : 'legendSelect', name: 'Total alerts' });
    chart.setOption({ yAxis: [{ show: !focus }, { splitLine: { show: focus } }] });
  }, [focus, dark]);
  useEffect(() => {
    const chart = instance.current;
    if (!chart || !onInspect) return;

    const selectBucket = (index: number, selectedSeverity = '') => {
      const selected = series[index];
      if (!selected?.since || !selected.until) return;
      setBucket(selected.since);
      setSeverity(selectedSeverity);
    };
    const seriesClicks = new WeakSet<object>();
    const inspect = (event: unknown) => {
      const params = event as { componentType?: string; dataIndex?: number; seriesId?: string; event?: object };
      if (params.componentType !== 'series' || params.dataIndex === undefined) return;
      if (params.event) seriesClicks.add(params.event);
      selectBucket(params.dataIndex, params.seriesId === 'critical' || params.seriesId === 'high' ? params.seriesId : '');
    };
    const canvas = chart.getZr();
    const inspectBackground = (event: { offsetX: number; offsetY: number }) => {
      const pixel = [event.offsetX, event.offsetY];
      if (!chart.containPixel({ gridIndex: 0 }, pixel)) return;
      const index = chart.convertFromPixel({ xAxisIndex: 0 }, event.offsetX);
      // A series click carries the severity. Let it take precedence over the plot click.
      queueMicrotask(() => {
        if (typeof index === 'number' && !seriesClicks.has(event)) selectBucket(index);
      });
    };
    chart.on('click', inspect);
    canvas.on('click', inspectBackground);
    return () => {
      chart.off('click', inspect);
      canvas.off('click', inspectBackground);
    };
  }, [series, dark, onInspect]);

  const zoomToBucket = () => {
    if (!point) return;
    const index = series.indexOf(point);
    instance.current?.dispatchAction({
      type: 'dataZoom',
      startValue: Math.max(0, index - 2),
      endValue: Math.min(series.length - 1, index + 2),
    });
  };
  const totals = series.reduce((t, p) => ({ critical: t.critical + p.critical, high: t.high + p.high }), { critical: 0, high: 0 });
  return <div className="trend-explorer">
    <div className="trend-controls">
      <span className="trend-sev-total">Critical <b>{totals.critical}</b> · High <b>{totals.high}</b></span>
      <span>{onInspect ? 'Select a time bucket to inspect it' : 'Hover over a bucket for counts'} · Drag the range slider to zoom</span>
      <button type="button" className={`btn small${focus ? ' primary' : ''}`} aria-pressed={focus} onClick={() => setFocus((active) => !active)}>
        {focus ? 'Show all alerts' : 'Focus critical & high'}
      </button>
      <button type="button" className="btn small" disabled={series.length < 2} onClick={() => instance.current?.dispatchAction({ type: 'dataZoom', start: 50, end: 100 })}>Recent half</button>
      <button type="button" className="btn small" disabled={series.length < 2} onClick={() => instance.current?.dispatchAction({ type: 'dataZoom', start: 0, end: 100 })}>Reset zoom</button>
    </div>
    <div ref={ref} className="chart" role="img" aria-label="Alert activity by severity. Use the range controls to zoom and the legend to toggle series." />
    {onInspect && <div className="trend-inspection">
      <div className="trend-selection" role="status">
        {point ? <><strong>{point.day}</strong><span>{point.alerts} total · {point.critical} critical · {point.high} high</span></> : 'Select a time bucket for alert counts and drill-down.'}
      </div>
      <div className="chart-drilldown">
        <select aria-label="Alert time bucket" value={point ? bucket : ''} onChange={(event) => setBucket(event.target.value)}>
          <option value="">Choose a time bucket</option>
          {series.filter((p) => p.since && p.until).map((p) => <option key={p.since} value={p.since}>{p.day} · {p.alerts} alerts</option>)}
        </select>
        <select aria-label="Chart severity" value={severity} onChange={(event) => setSeverity(event.target.value)}>
          <option value="">All severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
        </select>
        <button type="button" className="btn small" disabled={!point || series.length < 2} onClick={zoomToBucket}>Zoom to bucket</button>
        <button type="button" className="btn small primary" disabled={!point} onClick={() => { if (point) onInspect(point, severity || undefined); }}>View matching alerts</button>
      </div>
    </div>}
  </div>;
}
