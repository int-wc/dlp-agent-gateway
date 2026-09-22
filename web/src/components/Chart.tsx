import type { CSSProperties } from 'react'
import ReactEChartsCore from 'echarts-for-react/lib/core'
import { BarChart, LineChart, PieChart } from 'echarts/charts'
import { GridComponent, LegendComponent, TooltipComponent } from 'echarts/components'
import * as echarts from 'echarts/core'
import type { EChartsOption } from 'echarts'
import { CanvasRenderer } from 'echarts/renderers'

echarts.use([BarChart, LineChart, PieChart, GridComponent, LegendComponent, TooltipComponent, CanvasRenderer])

export function Chart({ option, style }: { option: object; style?: CSSProperties }) {
  return <ReactEChartsCore echarts={echarts} option={option as EChartsOption} style={style} />
}
