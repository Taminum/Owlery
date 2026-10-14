import { Link, useLocation } from 'react-router-dom'
import { Construction } from 'lucide-react'
import { t } from '../i18n'

const MILESTONE: Record<string, string> = {
  '/traffic': 'M3',
  '/domains': 'M2',
  '/users': 'M2',
  '/nodes': 'M2',
}

export default function Placeholder() {
  const { pathname, search } = useLocation()
  const m = MILESTONE[pathname]
  return (
    <div className="flex flex-col items-center rounded-card border border-line bg-surface px-6 py-16 text-center">
      <span className="mb-4 grid h-12 w-12 place-items-center rounded-full border border-line bg-elevated text-cyan">
        <Construction size={22} aria-hidden />
      </span>
      <h1 className="text-lg font-semibold">{t('placeholder.title')}</h1>
      <p className="mt-1.5 max-w-md text-[13px] leading-5 text-muted">{t('placeholder.text')}</p>
      {m && <p className="mt-2 text-xs text-muted/80">{t('placeholder.milestone', { m })}</p>}
      <Link to={{ pathname: '/', search }} className="mt-5 rounded-control border border-line bg-elevated px-4 py-2 text-[13px] font-medium hover:border-cyan/60">
        {t('placeholder.action')}
      </Link>
    </div>
  )
}
