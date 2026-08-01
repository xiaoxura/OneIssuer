type BrandProps = {
  inverse?: boolean
  compact?: boolean
  className?: string
}

export function Brand({ inverse = false, compact = false, className = '' }: BrandProps) {
  return (
    <div className={`brand ${inverse ? 'brand--inverse' : ''} ${className}`.trim()}>
      <span className="brand__mark" aria-hidden="true">
        <svg viewBox="0 0 36 36">
          <rect x="1" y="1" width="34" height="34" rx="11" />
          <circle cx="18" cy="15.5" r="7.4" />
          <path d="M18 22.9v7" />
          <circle className="brand__keyhole" cx="18" cy="15.5" r="2.35" />
        </svg>
      </span>
      {!compact && (
        <span className="brand__wordmark">
          One<span>Issuer</span>
        </span>
      )}
    </div>
  )
}
