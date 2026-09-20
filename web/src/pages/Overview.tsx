import { Alert, Card, Col, Empty, List, Row, Skeleton, Tag } from 'antd'
import { CheckCircleOutlined, ClockCircleOutlined, SafetyCertificateOutlined, StopOutlined } from '@ant-design/icons'
import ReactECharts from 'echarts-for-react'
import { PageHeader } from '../components/PageHeader'
import { MetricCard } from '../components/MetricCard'
import { AuditTable, reasonLabel } from '../components/AuditTable'
import { useAudits, useExceptions, useReport } from '../hooks/useOperations'

export function Overview() {
  const report = useReport(7)
  const audits = useAudits()
  const exceptions = useExceptions()
  const counts = report.data?.counts ?? { allow: 0, review: 0, block: 0 }
  const pending = exceptions.data?.filter(item => item.status === 'pending') ?? []
  const days = Object.keys(report.data?.daily_counts ?? {}).sort()
  const trend = {
    tooltip: { trigger: 'axis' }, legend: { data: ['允许', '待复核', '阻断'], bottom: 0 },
    grid: { left: 42, right: 18, top: 24, bottom: 48 }, xAxis: { type: 'category', data: days.map(day => day.slice(5)), boundaryGap: false },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#edf1f6' } } },
    series: [
      { name: '允许', type: 'line', smooth: true, symbol: 'circle', data: days.map(day => report.data?.daily_counts[day]?.allow ?? 0), lineStyle: { color: '#17a673' }, itemStyle: { color: '#17a673' }, areaStyle: { color: '#17a67312' } },
      { name: '待复核', type: 'line', smooth: true, symbol: 'circle', data: days.map(day => report.data?.daily_counts[day]?.review ?? 0), lineStyle: { color: '#e39b32' }, itemStyle: { color: '#e39b32' } },
      { name: '阻断', type: 'line', smooth: true, symbol: 'circle', data: days.map(day => report.data?.daily_counts[day]?.block ?? 0), lineStyle: { color: '#db5a5a' }, itemStyle: { color: '#db5a5a' } },
    ],
  }
  return <>
    <PageHeader eyebrow="Security operations" title="风险态势总览" description="聚焦需要人工处理的事件、阻断结果和策略反馈。" />
    {report.isError && <Alert type="error" showIcon message="运营数据读取失败" description={(report.error as Error).message} />}
    <Row gutter={[16, 16]}>
      <Col xs={24} sm={12} xl={6}><MetricCard label="近 7 天检查" value={report.data?.total ?? '—'} note="所有经过网关的上传" icon={<SafetyCertificateOutlined />} /></Col>
      <Col xs={24} sm={12} xl={6}><MetricCard label="待人工复核" value={counts.review} note="需要运营人员确认" tone="review" icon={<ClockCircleOutlined />} /></Col>
      <Col xs={24} sm={12} xl={6}><MetricCard label="已阻断" value={counts.block} note="未向下游发送" tone="block" icon={<StopOutlined />} /></Col>
      <Col xs={24} sm={12} xl={6}><MetricCard label="正常允许" value={counts.allow} note="通过内容策略检查" tone="allow" icon={<CheckCircleOutlined />} /></Col>
    </Row>
    <Row gutter={[16, 16]} className="section-row">
      <Col xs={24} xl={16}><Card title="风险趋势" extra={<span className="muted">UTC · 最近 7 天</span>} className="chart-card">{report.isLoading ? <Skeleton active /> : days.length ? <ReactECharts option={trend} style={{ height: 310 }} /> : <Empty description="产生审计事件后显示趋势" />}</Card></Col>
      <Col xs={24} xl={8}><Card title="待处理例外" extra={<Tag color={pending.length ? 'orange' : 'green'}>{pending.length} 项</Tag>} className="queue-card"><List dataSource={pending.slice(0, 6)} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有待审批例外" /> }} renderItem={item => <List.Item><List.Item.Meta title={`#${item.id} · ${item.actor}`} description={item.justification} /><Tag>{item.destination}</Tag></List.Item>} /></Card></Col>
    </Row>
    <Card title="最近高风险事件" extra={<span className="muted">点击行查看完整证据</span>} className="section-card">
      <AuditTable audits={(audits.data ?? []).filter(item => item.action !== 'allow').slice(0, 8)} loading={audits.isLoading} incidentsOnly />
    </Card>
    {Object.keys(report.data?.false_positive_policy_candidates ?? {}).length > 0 && <Alert className="section-row" type="warning" showIcon message="发现策略优化候选" description={Object.entries(report.data?.false_positive_policy_candidates ?? {}).map(([reason, count]) => `${reasonLabel(reason)}：${count} 条误报`).join('；')} />}
  </>
}

