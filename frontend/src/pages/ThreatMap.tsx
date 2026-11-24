import { keepPreviousData, useQuery } from '@tanstack/react-query';
import * as echarts from 'echarts/core';
import { GeoComponent, TooltipComponent } from 'echarts/components';
import { CanvasRenderer } from 'echarts/renderers';
import { useEffect, useRef, useState } from 'react';
import { useOutletContext } from 'react-router-dom';
import type { GeometryCollection, Topology } from 'topojson-specification';
import { ErrorBox, Loading, PageHead, Sev } from '../components/ui';
import { get } from '../lib/api';
import { REFRESH_MS } from '../lib/refresh';

echarts.use([GeoComponent, TooltipComponent, CanvasRenderer]);

type Country = { country: string; country_name: string; count: number; max_severity: string; ips: string[] };
export type MapData = {
  soc: { label: string };
  countries: Country[];
  total_threats: number;
  unique_sources: number;
  unique_countries: number;
};

const atlasNames: Record<string, string> = {
  'United States': 'United States of America', 'The Netherlands': 'Netherlands', 'Czech Republic': 'Czechia',
  'Ivory Coast': "Côte d'Ivoire", 'Bosnia and Herzegovina': 'Bosnia and Herz.',
  'Central African Republic': 'Central African Rep.', 'Democratic Republic of the Congo': 'Dem. Rep. Congo',
  'Republic of the Congo': 'Congo', 'Dominican Republic': 'Dominican Rep.', 'Equatorial Guinea': 'Eq. Guinea',
  'Solomon Islands': 'Solomon Is.', 'South Sudan': 'S. Sudan', 'Western Sahara': 'W. Sahara',
};
const atlasName = (country: Country) => atlasNames[country.country_name] ?? country.country_name;
const number = new Intl.NumberFormat();

async function registerWorld() {
  if (echarts.getMap('threat-world')) return;
  const [atlas, { feature }, { geoEquirectangular, geoStream }] = await Promise.all([
    import('world-atlas/countries-110m.json'), import('topojson-client'), import('d3-geo'),
  ]);
  const topology = atlas.default as unknown as Topology<{ countries: GeometryCollection<{ name: string }> }>;
  const world = feature(topology, topology.objects.countries);
  const projection = geoEquirectangular().scale(180 / Math.PI).translate([0, 0]).precision(0);

  for (const country of world.features) {
    const geometry = country.geometry;
    if (geometry.type !== 'Polygon' && geometry.type !== 'MultiPolygon') continue;
    const polygons = geometry.type === 'Polygon' ? [geometry.coordinates] : geometry.coordinates;
    const clipped = polygons.flatMap((polygon) => {
      const exterior = polygon[0];
      // The affected atlas polygons are single-ring shapes spanning ±180°.
      if (polygon.length !== 1 || !exterior.some(([x], i) => i > 0 && Math.abs(x - exterior[i - 1][0]) > 180)) {
        return [polygon];
      }
      const pieces: number[][][] = [];
      let ring: number[][] = [];
      geoStream({ type: 'Polygon', coordinates: polygon }, projection.stream({
        polygonStart() {},
        polygonEnd() {},
        lineStart() { ring = []; },
        lineEnd() {
          if (ring.length >= 3) pieces.push([...ring, ring[0]]);
        },
        point(x, y) { ring.push([x, -y]); },
      }));
      return pieces.map((piece) => [piece]);
    });
    country.geometry = { type: 'MultiPolygon', coordinates: clipped };
  }

  echarts.registerMap('threat-world', JSON.stringify(world));
}

function redScale(ratio: number, dark: boolean) {
  if (dark) {
    return `rgb(${Math.round(131 + ratio * 124)}, ${Math.round(55 - ratio * 23)}, ${Math.round(73 - ratio * 18)})`;
  }
  const shade = Math.round(240 - ratio * 200);
  return `rgb(255, ${shade}, ${shade})`;
}

function countryFlag(code: string) {
  if (!/^[A-Z]{2}$/.test(code)) return '🌐';
  return String.fromCodePoint(...[...code].map((char) => char.charCodeAt(0) - 65 + 0x1f1e6));
}

export function WorldMap({ data, dark, compact = false }: { data: MapData; dark: boolean; compact?: boolean }) {
  const element = useRef<HTMLDivElement>(null);
  const chartRef = useRef<echarts.EChartsType | null>(null);
  const [ready, setReady] = useState(false);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    let active = true;
    let observer: ResizeObserver | undefined;
    void registerWorld().then(() => {
      if (!active || !element.current) return;
      const chart = echarts.init(element.current);
      chartRef.current = chart;
      chart.setOption({
        geo: {
          map: 'threat-world', roam: !compact, zoom: 1, aspectScale: 1,
          scaleLimit: { min: 1, max: 6 },
          label: { show: false }, emphasis: { label: { show: false } },
        },
      });
      observer = new ResizeObserver(() => chart.resize());
      observer.observe(element.current);
      setReady(true);
    }).catch(() => { if (active) setFailed(true); });
    return () => {
      active = false;
      observer?.disconnect();
      chartRef.current?.dispose();
      chartRef.current = null;
    };
  }, [compact]);

  useEffect(() => {
    const chart = chartRef.current;
    if (!ready || !chart) return;
    const land = dark ? '#35465e' : '#dce5ee';
    const border = dark ? '#61748f' : '#98aabd';
    const ink = dark ? '#e6ebf2' : '#22344a';
    const max = Math.max(1, ...data.countries.map((c) => c.count));
    const byName = new Map(data.countries.map((c) => [atlasName(c), c]));
    chart.setOption({
      tooltip: {
        trigger: 'item', renderMode: 'richText', confine: true,
        backgroundColor: dark ? '#171d27' : '#fff', borderColor: border, textStyle: { color: ink, fontSize: 13 },
        formatter: (p: { name: string }) => {
          const country = byName.get(p.name);
          return country ? `${country.country_name}\n${number.format(country.count)} alerts · ${country.max_severity}` : p.name;
        },
      },
      geo: {
        itemStyle: { areaColor: land, borderColor: border, borderWidth: .7 },
        emphasis: { itemStyle: { areaColor: dark ? '#4b6380' : '#c0d4e7' }, label: { show: false } },
        tooltip: { show: true },
        regions: data.countries.map((country) => ({
          name: atlasName(country),
          itemStyle: { areaColor: redScale(country.count / max, dark) },
          emphasis: { itemStyle: { areaColor: '#cc2244', borderColor: '#ff4466', borderWidth: 2 } },
        })),
      },
    });
  }, [ready, data, dark]);

  return (
    <section className={compact ? "threat-map-panel overview-map" : "panel threat-map-panel"} aria-label="Geographic alert overview">
      <div className="threat-map-stage">
        <div className="threat-map-canvas" ref={element} role="img" aria-label="World map with red shading for alert volume" />
        {ready && !compact && <div className="threat-red-legend" aria-label="Alert volume, low to high">
          <span>High</span>
          <i style={{ background: `linear-gradient(${redScale(1, dark)}, ${redScale(0, dark)})` }} />
          <span>Low</span>
        </div>}
        {!ready && <div className="threat-map-message" role="status">{failed ? 'The map could not load. Country details are still available.' : 'Loading map…'}</div>}
      </div>
    </section>
  );
}

export default function ThreatMap() {
  const { dark } = useOutletContext<{ dark: boolean }>();
  const [days, setDays] = useState(7);
  const q = useQuery({
    queryKey: ['threat-map', days],
    queryFn: () => get<MapData>('/api/threat-map', { days }),
    placeholderData: keepPreviousData, refetchInterval: REFRESH_MS,
  });
  const data = q.data;

  return (
    <>
      <PageHead title="Threat map" sub="Geographic origins of threats targeting your infrastructure." eyebrow="THREAT INTELLIGENCE">
        <select aria-label="Time range" value={days} onChange={(e) => setDays(Number(e.target.value))} className="select">
          {[1, 7, 30, 90].map((n) => <option key={n} value={n}>{n === 1 ? 'Last 24 hours' : `Last ${n} days`}</option>)}
        </select>
      </PageHead>
      {q.error && <ErrorBox error={q.error} />}
      {!data && q.isPending && <Loading />}
      {data && <>
        <div className="metrics">
          <div className="metric"><span>Total threats</span><strong>{number.format(data.total_threats)}</strong><small>alerts with geo data</small></div>
          <div className="metric"><span>Unique sources</span><strong>{number.format(data.unique_sources)}</strong><small>distinct IP addresses</small></div>
          <div className="metric"><span>Countries</span><strong>{number.format(data.unique_countries)}</strong><small>origin countries</small></div>
          <div className="metric"><span>Target</span><strong>{data.soc.label.split('–')[1]?.trim() || 'SOC'}</strong><small>destination infrastructure</small></div>
        </div>
        <div className="threat-map-grid">
          <WorldMap data={data} dark={dark} />
          <section className="panel threat-origins">
            <div className="threat-map-toolbar">
              <div><h2>Top origins</h2><p>{data.countries.length} countries detected</p></div>
            </div>
            <div className="threat-origin-list">
              {data.countries.slice(0, 25).map((country, index) => (
                <div className="threat-origin-row" key={country.country}>
                  <span className="threat-origin-rank">{index + 1}</span>
                  <span className="threat-origin-flag" aria-hidden="true">{countryFlag(country.country)}</span>
                  <span className="threat-origin-country"><strong>{country.country_name}</strong><small>{country.ips.length === 5 ? '5+' : country.ips.length} sources</small></span>
                  <span className="threat-origin-count"><strong>{number.format(country.count)}</strong><Sev v={country.max_severity} /></span>
                </div>
              ))}
              {!data.countries.length && <div className="empty">No geo data available</div>}
            </div>
          </section>
        </div>
      </>}
    </>
  );
}
