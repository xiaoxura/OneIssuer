import { useId, type ComponentType, type ReactNode, type SVGProps } from 'react'
import { ArrowDownRight, ArrowUpRight, X } from 'lucide-react'
import { useI18n } from '../i18n'
import { useDialogFocus } from './useDialogFocus'

export type IconComponent = ComponentType<SVGProps<SVGSVGElement> & { size?: number | string }>

type PageHeaderProps = {
  eyebrow?: string
  title: string
  description: string
  actions?: ReactNode
}

export function PageHeader({ eyebrow, title, description, actions }: PageHeaderProps) {
  return (
    <header className="page-header">
      <div>
        {eyebrow && <span className="page-header__eyebrow">{eyebrow}</span>}
        <h1>{title}</h1>
        <p>{description}</p>
      </div>
      {actions && <div className="page-header__actions">{actions}</div>}
    </header>
  )
}

type AvatarProps = {
  initials: string
  tone?: 'mint' | 'blue' | 'amber' | 'rose' | 'violet' | 'slate'
  size?: 'small' | 'medium' | 'large'
}

export function Avatar({ initials, tone = 'mint', size = 'medium' }: AvatarProps) {
  return <span className={`avatar avatar--${tone} avatar--${size}`}>{initials}</span>
}

export function StatusPill({
  children,
  tone = 'neutral',
  dot = true,
}: {
  children: ReactNode
  tone?: 'success' | 'warning' | 'danger' | 'info' | 'neutral'
  dot?: boolean
}) {
  return (
    <span className={`status-pill status-pill--${tone}`}>
      {dot && <span className="status-pill__dot" aria-hidden="true" />}
      {children}
    </span>
  )
}

type MetricCardProps = {
  label: string
  value: string
  change: string
  direction?: 'up' | 'down'
  icon: IconComponent
  detail: string
}

export function MetricCard({
  label,
  value,
  change,
  direction = 'up',
  icon: Icon,
  detail,
}: MetricCardProps) {
  const TrendIcon = direction === 'up' ? ArrowUpRight : ArrowDownRight
  return (
    <article className="metric-card">
      <div className="metric-card__topline">
        <span>{label}</span>
        <span className="metric-card__icon">
          <Icon size={18} />
        </span>
      </div>
      <strong>{value}</strong>
      <div className="metric-card__foot">
        <span className={`trend trend--${direction}`}>
          <TrendIcon size={14} /> {change}
        </span>
        <span>{detail}</span>
      </div>
    </article>
  )
}

export function Modal({
  title,
  description,
  children,
  onClose,
}: {
  title: string
  description: string
  children: ReactNode
  onClose: () => void
}) {
  const { t } = useI18n()
  const titleId = useId()
  const descriptionId = useId()
  const dialogRef = useDialogFocus<HTMLElement>(onClose)

  return (
    <div className="modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section
        aria-describedby={descriptionId}
        aria-labelledby={titleId}
        aria-modal="true"
        className="modal"
        ref={dialogRef}
        role="dialog"
        tabIndex={-1}
        onMouseDown={(event) => event.stopPropagation()}
      >
        <header className="modal__header">
          <div>
            <h2 id={titleId}>{title}</h2>
            <p id={descriptionId}>{description}</p>
          </div>
          <button className="icon-button" onClick={onClose} type="button" aria-label={t('common.close')}>
            <X size={18} />
          </button>
        </header>
        {children}
      </section>
    </div>
  )
}
