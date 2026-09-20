import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, description, extra }: { eyebrow: string; title: string; description: string; extra?: ReactNode }) {
  return <div className="page-heading">
    <div className="page-heading-copy"><div className="eyebrow"><span />{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>
    {extra && <div className="page-actions">{extra}</div>}
  </div>
}
