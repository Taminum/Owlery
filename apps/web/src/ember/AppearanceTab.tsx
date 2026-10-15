import { t, type MsgKey } from '../i18n'
import { Card } from '../components/ui'
import { KAWAII_THEMES, MASCOT_SIZES, setKawaii, useKawaii, type MascotSize } from './settings'

function Toggle({ id, label, hint, checked, disabled, onChange }: { id: string; label: string; hint?: string; checked: boolean; disabled?: boolean; onChange: (v: boolean) => void }) {
  return (
    <label htmlFor={id} className={`flex items-start gap-3 py-2 text-[13px] ${disabled ? 'opacity-50' : ''}`}>
      <input id={id} type="checkbox" className="mt-0.5" checked={checked} disabled={disabled} onChange={(e) => onChange(e.target.checked)} />
      <span><span className="font-medium">{label}</span>{hint && <span className="block text-xs text-muted">{hint}</span>}</span>
    </label>
  )
}

/** Kawaii Mode: a decorative, optional look and a mascot. Remembered in this browser only. */
export function AppearanceTab() {
  const s = useKawaii()
  return (
    <div className="space-y-4">
      <Card title={t('kw.title')} note={t('kw.note')}>
        <Toggle id="kw-enabled" label={t('kw.enabled')} hint={t('kw.enabled.hint')} checked={s.enabled} onChange={(v) => setKawaii({ enabled: v })} />
        <div className="mt-2 grid gap-1">
          <label htmlFor="kw-theme" className="text-[13px] font-medium">{t('kw.theme')}</label>
          <select id="kw-theme" className="h-10 max-w-xs rounded-control border border-line bg-canvas px-3 text-[13px] disabled:opacity-50" value={s.theme} disabled={!s.enabled}
            onChange={(e) => setKawaii({ theme: e.target.value as (typeof KAWAII_THEMES)[number] })}>
            {KAWAII_THEMES.map((x) => <option key={x} value={x}>{t(`kw.theme.${x}` as MsgKey)}</option>)}
          </select>
        </div>
      </Card>
      <Card title={t('kw.mascot.title')}>
        <Toggle id="kw-mascot" label={t('kw.mascot.show')} checked={s.mascot} disabled={!s.enabled} onChange={(v) => setKawaii({ mascot: v })} />
        <div className="grid gap-1 py-2">
          <label htmlFor="kw-size" className="text-[13px] font-medium">{t('kw.size')}</label>
          <select id="kw-size" className="h-10 max-w-xs rounded-control border border-line bg-canvas px-3 text-[13px] disabled:opacity-50" value={s.size} disabled={!s.enabled || !s.mascot}
            onChange={(e) => setKawaii({ size: e.target.value as MascotSize })}>
            {(Object.keys(MASCOT_SIZES) as MascotSize[]).map((x) => <option key={x} value={x}>{t(`kw.size.${x}` as MsgKey)}</option>)}
          </select>
          <span className="text-xs text-muted">{t('kw.size.hint')}</span>
          {s.pos && <div><button type="button" className="mt-1 text-xs text-muted underline hover:text-fg" onClick={() => setKawaii({ pos: null })}>{t('kw.reset')}</button></div>}
        </div>
        <Toggle id="kw-comments" label={t('kw.comments')} checked={s.comments} disabled={!s.enabled || !s.mascot} onChange={(v) => setKawaii({ comments: v })} />
        <Toggle id="kw-anim" label={t('kw.animations')} checked={s.animations} disabled={!s.enabled || !s.mascot} onChange={(v) => setKawaii({ animations: v })} />
        <Toggle id="kw-storm" label={t('kw.storm')} hint={t('kw.storm.hint')} checked={s.itemStorm} disabled={!s.enabled || !s.mascot || !s.animations} onChange={(v) => setKawaii({ itemStorm: v })} />
        <Toggle id="kw-reduced" label={t('kw.reduced')} hint={t('kw.reduced.hint')} checked={s.reduced} disabled={!s.enabled} onChange={(v) => setKawaii({ reduced: v })} />
      </Card>
    </div>
  )
}
