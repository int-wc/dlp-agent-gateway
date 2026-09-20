import type { ReactNode } from 'react'

export function PageHeader({ eyebrow, title, description, extra }: { eyebrow: string; title: string; description: string; extra?: ReactNode }) {
  return <div className="page-heading">
    <div><div className="eyebrow">{eyebrow}</div><h1>{title}</h1><p>{description}</p></div>
    {extra && <div className="page-actions">{extra}</div>}
  </div>
}

