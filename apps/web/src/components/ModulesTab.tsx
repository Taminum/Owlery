import { useState } from 'react'
import { t, type MsgKey } from '../i18n'
import { errorText } from '../lib/errors'
import { MODULES, setModule, useModulesOff, type ModuleId } from '../lib/modules'
import { Card } from './ui'

/** The owner turns the optional parts of the program on and off. */
export function ModulesTab() {
  const off = useModulesOff()
  const [busy, setBusy] = useState<ModuleId | null>(null)
  const [error, setError] = useState('')
  async function flip(id: ModuleId) {
    setBusy(id)
    setError('')
    try {
      await setModule(id, off.has(id))
    } catch (e) {
      setError(errorText(e))
    } finally {
      setBusy(null)
    }
  }
  return (
    <Card title={t('mod.title')} note={t('mod.subtitle')}>
      {error && <p role="alert" className="mb-3 text-[13px] text-red">{error}</p>}
      <ul className="divide-y divide-line">
        {MODULES.map((id) => {
          const on = !off.has(id)
          return (
            <li key={id} className="flex items-center justify-between gap-4 py-3">
              <div className="min-w-0">
                <div className="text-[14px] font-medium text-fg">{t(`mod.${id}` as MsgKey)}</div>
                <p className="text-xs text-muted">{t(`mod.${id}.text` as MsgKey)}</p>
              </div>
              <button type="button" role="switch" aria-checked={on} aria-label={t(`mod.${id}` as MsgKey)} disabled={busy !== null} onClick={() => void flip(id)}
                className={`relative h-6 w-11 shrink-0 rounded-full transition-colors disabled:opacity-50 ${on ? 'bg-cyan' : 'bg-line'}`}>
                <span className={`absolute top-0.5 h-5 w-5 rounded-full bg-white transition-all ${on ? 'left-[22px]' : 'left-0.5'}`} />
                <span className="sr-only">{on ? t('mod.on') : t('mod.off')}</span>
              </button>
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
