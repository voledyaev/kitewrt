import Chart from 'react-apexcharts'
import type { ApexOptions } from 'apexcharts'
import { useMemo } from 'react'

export interface AreaSeries {
  name: string
  color: string
  data: number[] // oldest → newest
}

// Shared smooth area chart for the dashboard's time-series cards (traffic,
// memory, connections). One component → one lazily-loaded ApexCharts chunk.
export function AreaChart({
  series,
  height = 200,
  yFormat,
}: {
  series: AreaSeries[]
  height?: number
  yFormat: (v: number) => string
}) {
  const points = Math.max(0, ...series.map((s) => s.data.length))

  const apexSeries = useMemo(
    () =>
      series.map((s) => ({
        name: s.name,
        // x = seconds-ago: oldest negative … 0 = now.
        data: s.data.map((y, i) => ({ x: i - (s.data.length - 1), y })),
      })),
    [series],
  )

  const options: ApexOptions = useMemo(
    () => ({
      chart: {
        type: 'area',
        toolbar: { show: false },
        zoom: { enabled: false },
        fontFamily: 'inherit',
        foreColor: '#7d8590',
        animations: { enabled: true, dynamicAnimation: { enabled: true, speed: 350 } },
      },
      colors: series.map((s) => s.color),
      dataLabels: { enabled: false },
      stroke: { curve: 'smooth', width: 2 },
      fill: {
        type: 'gradient',
        gradient: { shadeIntensity: 1, opacityFrom: 0.35, opacityTo: 0.02, stops: [0, 100] },
      },
      grid: { borderColor: '#21262d', strokeDashArray: 3, padding: { left: 8, right: 8 } },
      xaxis: {
        type: 'numeric',
        tickAmount: 6,
        axisBorder: { show: false },
        axisTicks: { show: false },
        labels: { formatter: (v) => `${Math.round(Number(v))}s` },
      },
      yaxis: { tickAmount: 4, labels: { formatter: (v) => yFormat(Number(v)) } },
      tooltip: {
        theme: 'dark',
        x: { formatter: (v) => `${Math.round(Number(v))}s` },
        y: { formatter: (v) => yFormat(Number(v)) },
      },
      legend: { show: false },
    }),
    [series, yFormat],
  )

  if (points < 2) {
    return (
      <div
        className="flex items-center justify-center text-sm text-base-content/40"
        style={{ height }}
      >
        gathering data…
      </div>
    )
  }
  return <Chart type="area" height={height} options={options} series={apexSeries} />
}
