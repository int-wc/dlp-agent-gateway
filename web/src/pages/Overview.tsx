import { useMemo, useState } from 'react'
import { Alert, Card, Col, Empty, List, Progress, Row, Segmented, Skeleton, Space, Tag } from 'antd'
import {
  AlertOutlined, CheckCircleOutlined, ClockCircleOutlined, SafetyCertificateOutlined,
} from '@ant-design/icons'
import { Chart } from '../components/Chart'
import { PageHeader } from '../components/PageHeader'
import { MetricCard } from '../components/MetricCard'
import { actionMeta, formatDateTime, reasonLabel } from '../components/AuditTable'
import { useAudits, useFeedback, useReport } from '../hooks/useOperations'

function durationLabel(milliseconds: number | null) {
  if (milliseconds === null) return '—'
  const minutes = Math.max(0, Math.round(milliseconds / 60000))
  if (minutes < 60) return `${minutes}m`
  return `${(minutes / 60).toFixed(1)}h`
}

export function Overview() {
  const [days, setDays] = useState(7)
  const report = useReport(days)
  const audits = useAudits()
  const feedback = useFeedback()
  const counts = report.data?.counts ?? { allow: 0, review: 0, block: 0 }
  const totalRisks = counts.review + counts.block
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000
  const windowAudits = useMemo(() => (audits.data ?? []).filter(item => new Date(item.created_at).getTime() >= cutoff), [audits.data, cutoff])
  const riskAudits = windowAudits.filter(item => item.action !== 'allow')
  const feedbackMap = new Map((feedback.data ?? []).map(item => [item.audit_id, item]))
  const remediated = riskAudits.filter(item => feedbackMap.has(item.id))
  const activeRisks = riskAudits.filter(item => !feedbackMap.has(item.id))
  const operations = report.data?.operations
  const remediationRate = totalRisks ? Math.round((operations?.remediated ?? remediated.length) / totalRisks * 100) : null
  const meanResponse = operations?.mean_time_to_remediate_seconds == null ? null : operations.mean_time_to_remediate_seconds * 1000
  const coverage = operations?.inspection_coverage_percent ?? null
  const daysOnChart = Object.keys(report.data?.daily_counts ?? {}).sort()

  const topReasons = Object.entries(report.data?.top_reasons ?? {}).sort((a, b) => b[1] - a[1]).slice(0, 5)
  const maxReasonCount = topReasons[0]?.[1] ?? 1
  const trend = {
    color: ['#e2a33e', '#d95858', '#2f72db'],
    tooltip: { trigger: 'axis', backgroundColor: '#152238', borderWidth: 0, textStyle: { color: '#fff' } },
    legend: { data: ['待复核', '阻断', '扫描总量'], top: 0, right: 4, itemWidth: 9, itemHeight: 9 },
    grid: { left: 38, right: 18, top: 48, bottom: 32 },
    xAxis: { type: 'category', data: daysOnChart.map(day => day.slice(5)), axisLine: { lineStyle: { color: '#dfe5ed' } }, axisTick: { show: false } },
    yAxis: { type: 'value', minInterval: 1, splitLine: { lineStyle: { color: '#eef2f6' } } },
    series: [
      { name: '待复核', type: 'bar', stack: 'risk', barMaxWidth: 18, data: daysOnChart.map(day => report.data?.daily_counts[day]?.review ?? 0), itemStyle: { borderRadius: [0, 0, 3, 3] } },
      { name: '阻断', type: 'bar', stack: 'risk', barMaxWidth: 18, data: daysOnChart.map(day => report.data?.daily_counts[day]?.block ?? 0), itemStyle: { borderRadius: [3, 3, 0, 0] } },
      { name: '扫描总量', type: 'line', smooth: true, symbol: 'circle', symbolSize: 6, data: daysOnChart.map(day => { const value = report.data?.daily_counts[day]; return (value?.allow ?? 0) + (value?.review ?? 0) + (value?.block ?? 0) }), lineStyle: { width: 2 }, areaStyle: { color: 'rgba(47, 114, 219, .08)' } },
    ],
  }
  const posture = {
    tooltip: { trigger: 'item' },
    series: [{ type: 'pie', radius: ['68%', '86%'], center: ['50%', '48%'], silent: true, label: { show: false }, data: [
      { name: '待复核', value: counts.review, itemStyle: { color: '#e2a33e' } },
      { name: '阻断', value: counts.block, itemStyle: { color: '#d95858' } },
      { name: '允许', value: counts.allow, itemStyle: { color: '#dce9e4' } },
    ] }]
  }

  return <>
    <PageHeader eyebrow="Security posture" title="风险态势总览" description="从扫描覆盖、活跃风险到处置效率，快速判断今天应该优先处理什么。" extra={<Segmented value={days} onChange={value => setDays(Number(value))} options={[{ label: '7 天', value: 7 }, { label: '30 天', value: 30 }, { label: '90 天', value: 90 }]} />} />
    {report.isError && <Alert type="error" showIcon message="运营数据读取失败" description={(report.error as Error).message} />}

    <div className="overview-metrics">
      <MetricCard label="活跃风险" value={operations?.active_risks ?? activeRisks.length} note={`${totalRisks} 个风险事件进入运营队列`} tone="block" icon={<AlertOutlined />} />
      <MetricCard label="处置率" value={remediationRate ?? '—'} suffix={remediationRate === null ? undefined : '%'} note={`${operations?.remediated ?? remediated.length} / ${totalRisks} 已记录结论`} tone="allow" icon={<CheckCircleOutlined />} />
      <MetricCard label="平均响应时间" value={durationLabel(meanResponse)} note="从检测到人工处置结论" tone="review" icon={<ClockCircleOutlined />} />
      <MetricCard label="扫描覆盖" value={coverage ?? '—'} suffix={coverage === null ? undefined : '%'} note={`${report.data?.total ?? windowAudits.length} 次上传纳入覆盖统计`} tone="allow" icon={<SafetyCertificateOutlined />} />
    </div>

    <Row gutter={[16, 16]} className="section-row">
      <Col xs={24} xl={16}><Card title={<div className="card-title-stack"><strong>风险与扫描趋势</strong><span>识别风险峰值和流量变化</span></div>} extra={<span className="muted">UTC · 最近 {days} 天</span>} className="chart-card overview-trend">{report.isLoading ? <Skeleton active /> : daysOnChart.length ? <Chart option={trend} style={{ height: 300 }} /> : <Empty description="产生审计事件后显示趋势" />}</Card></Col>
      <Col xs={24} xl={8}><Card title={<div className="card-title-stack"><strong>风险分布</strong><span>当前时间窗口的判定结构</span></div>} className="chart-card posture-card">
        {report.data?.total ? <div className="posture-chart"><Chart option={posture} style={{ height: 230 }} /><div className="posture-center"><strong>{riskAudits.length}</strong><span>风险事件</span></div></div> : <Empty description="暂无扫描数据" />}
        <div className="posture-legend"><span><i className="review" />待复核 <strong>{counts.review}</strong></span><span><i className="block" />阻断 <strong>{counts.block}</strong></span><span><i className="allow" />允许 <strong>{counts.allow}</strong></span></div>
      </Card></Col>
    </Row>

    <Row gutter={[16, 16]} className="section-row">
      <Col xs={24} xl={14}><Card title={<div className="card-title-stack"><strong>优先调查队列</strong><span>尚未记录人工结论的高风险事件</span></div>} extra={<a href="#incidents">查看全部</a>} className="operations-card">
        <List dataSource={activeRisks.slice(0, 5)} locale={{ emptyText: <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="当前没有待处置风险" /> }} renderItem={item => <List.Item className="risk-queue-item" onClick={() => { location.hash = 'incidents' }}>
          <div className={`queue-severity ${item.action}`}><span>{item.action === 'block' ? '高' : '中'}</span></div>
          <div className="queue-main"><strong>{item.filename}</strong><span>{item.actor} → {item.destination}</span></div>
          <div className="queue-meta"><Tag color={actionMeta[item.action].color}>{actionMeta[item.action].label}</Tag><span>{formatDateTime(item.created_at, 'time')}</span></div>
        </List.Item>} />
      </Card></Col>
      <Col xs={24} xl={10}><Card title={<div className="card-title-stack"><strong>高频检测信号</strong><span>策略与检测器命中排行</span></div>} className="operations-card">
        {topReasons.length ? <div className="reason-ranking">{topReasons.map(([reason, count], index) => <div key={reason}><div><span><b>{index + 1}</b>{reasonLabel(reason)}</span><strong>{count}</strong></div><Progress percent={Math.round(count / maxReasonCount * 100)} showInfo={false} strokeColor={index === 0 ? '#d95858' : '#4d7fd1'} trailColor="#edf1f5" size="small" /></div>)}</div> : <Empty image={Empty.PRESENTED_IMAGE_SIMPLE} description="暂无检测信号" />}
      </Card></Col>
    </Row>

    {Object.keys(report.data?.false_positive_policy_candidates ?? {}).length > 0 && <Alert className="section-row" type="warning" showIcon message="发现策略优化候选" description={<Space size={[8, 8]} wrap>{Object.entries(report.data?.false_positive_policy_candidates ?? {}).map(([reason, count]) => <Tag color="orange" key={reason}>{reasonLabel(reason)} · {count} 条误报</Tag>)}</Space>} />}
  </>
}
