import type { ReactNode } from 'react'

export function PageHeader({ title, description, extra }: { eyebrow?: string; title: string; description: string; extra?: ReactNode }) {
  return <div className="page-heading">
    <div className="page-heading-copy"><h1>{title}</h1><p>{description}</p></div>
    {extra && <div className="page-actions">{extra}</div>}
  </div>
}
