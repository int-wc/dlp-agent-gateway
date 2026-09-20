import { useState } from 'react'
import { Card, Col, Empty, Row, Segmented, Table, Tag } from 'antd'
import ReactECharts from 'echarts-for-react'
import { PageHeader } from '../components/PageHeader'
import { reasonLabel } from '../components/AuditTable'
import { useReport } from '../hooks/useOperations'

export function Reports() {
  const [days, setDays] = useState(30)
  const report = useReport(days)
  const counts = report.data?.counts ?? { allow: 0, review: 0, block: 0 }
  const actionChart = { tooltip: { trigger: 'item' }, legend: { bottom: 0 }, series: [{ type: 'pie', radius: ['52%', '76%'], center: ['50%', '45%'], label: { formatter: '{b}  {c}' }, data: [{ name: '允许', value: counts.allow, itemStyle: { color: '#17a673' } }, { name: '待复核', value: counts.review, itemStyle: { color: '#e39b32' } }, { name: '阻断', value: counts.block, itemStyle: { color: '#db5a5a' } }] }] }
  const transferData = Object.entries(report.data?.transfer_counts ?? {}).map(([name, value]) => ({ name, value }))
  const transferChart = { tooltip: { trigger: 'axis' }, grid: { left: 110, right: 30, top: 16, bottom: 26 }, xAxis: { type: 'value', minInterval: 1 }, yAxis: { type: 'category', data: transferData.map(item => item.name) }, series: [{ type: 'bar', data: transferData.map(item => item.value), itemStyle: { color: '#4778d6', borderRadius: [0, 5, 5, 0] } }] }
  const reasons = Object.entries(report.data?.top_reasons ?? {}).sort((a, b) => b[1] - a[1]).map(([reason, count]) => ({ reason, count }))
  return <>
    <PageHeader eyebrow="Risk analytics" title="运营报告" description="按统一时间窗口查看内容风险、传输结果和策略优化信号。" extra={<Segmented value={days} onChange={value => setDays(Number(value))} options={[{ label: '7 天', value: 7 }, { label: '30 天', value: 30 }, { label: '90 天', value: 90 }]} />} />
    <Row gutter={[16, 16]}><Col xs={24} xl={10}><Card title="内容判定分布" className="chart-card">{report.data?.total ? <ReactECharts option={actionChart} style={{ height: 330 }} /> : <Empty description="暂无报告数据" />}</Card></Col><Col xs={24} xl={14}><Card title="传输状态分布" className="chart-card"><ReactECharts option={transferChart} style={{ height: 330 }} /></Card></Col></Row>
    <Card title="高频命中原因" className="section-card"><Table rowKey="reason" dataSource={reasons} pagination={false} columns={[{ title: '原因', dataIndex: 'reason', render: value => reasonLabel(value) }, { title: '事件数', dataIndex: 'count', width: 140, render: value => <Tag color="blue">{value}</Tag> }, { title: '建议', render: (_, item) => report.data?.false_positive_policy_candidates[item.reason] ? '存在误报反馈，建议复盘阈值和作用域' : '保持观察并结合业务上下文复核' }]} /></Card>
  </>
}

