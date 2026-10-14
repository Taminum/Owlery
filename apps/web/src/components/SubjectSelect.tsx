import { t } from '../i18n'
import { useApp } from '../lib/context'
import { useAnalytics } from '../hooks/useAnalytics'
import type { SubjectsResponse } from '../lib/types'
import { controlCls } from './Popover'

/** "Whose traffic": everyone, one panel user, or one device behind the router. */
export function SubjectSelect({ value, onChange }: { value: string; onChange: (v: string) => void }) {
  const { filters } = useApp()
  const { data } = useAnalytics<SubjectsResponse>('subjects', filters)
  const subs = data?.subjects ?? []
  const group = (kind: string) => subs.filter((s) => s.kind === kind)
  const users = [...group('user'), ...group('raw')]
  const devices = group('device')
  const paths = group('path')
  const awg = group('awg').sort((a, b) => (a.subject.endsWith('|*') ? -1 : b.subject.endsWith('|*') ? 1 : 0))
  // Keep the current choice selectable even when it has no traffic in the new range.
  const known = value === '' || subs.some((s) => s.subject === value)
  return (
    <label className="flex items-center gap-2 text-[13px] text-muted">
      <span className="sr-only sm:not-sr-only">{t('an.subject')}</span>
      <select value={value} onChange={(e) => onChange(e.target.value)} aria-label={t('an.subject')} className={`${controlCls} max-w-[260px]`}>
        <option value="">{t('an.subject.all')}</option>
        {!known && <option value={value}>{t('an.subject.selected')}</option>}
        {users.length > 0 && (
          <optgroup label={t('an.subject.users')}>
            {users.map((s) => <option key={s.subject} value={s.subject}>{s.label}{s.panel_name ? ` · ${s.panel_name}` : ''}</option>)}
          </optgroup>
        )}
        {paths.length > 0 && (
          <optgroup label={t('an.subject.paths')}>
            {paths.map((s) => <option key={s.subject} value={s.subject}>{s.label}{s.panel_name ? ` · ${s.panel_name}` : ''}</option>)}
          </optgroup>
        )}
        {awg.length > 0 && (
          <optgroup label={t('an.subject.awg')}>
            {awg.map((s) => <option key={s.subject} value={s.subject}>{s.label}</option>)}
          </optgroup>
        )}
        {devices.length > 0 && (
          <optgroup label={t('an.subject.devices')}>
            {devices.map((s) => <option key={s.subject} value={s.subject}>{s.label}</option>)}
          </optgroup>
        )}
      </select>
    </label>
  )
}
