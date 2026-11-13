import { useMemo, useState } from 'react'
import { Pencil, Plus, Trash2 } from 'lucide-react'
import { t, type MsgKey } from '../i18n'
import { ApiError, api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { Chip } from './ui'
import { Field, GhostButton, Modal, PrimaryButton, inputCls } from './Modal'

export type Template = { id: string; os: 'linux' | 'windows'; name: string; command: string; note: string; danger: boolean }

function why(e: unknown): string {
  if (e instanceof ApiError) {
    const k = `tpl.err.${e.code}` as MsgKey
    const m = t(k)
    return m === k ? t('tpl.err.other') : m
  }
  return t('tpl.err.other')
}

/** The commands kept ready for this kind of machine: one click puts one into the open terminal. */
export function CommandTemplates({ os, send }: { os: 'linux' | 'windows'; send: (text: string, run: boolean) => boolean }) {
  const q = useLoad((sig) => api.get<{ templates: Template[] }>(`/api/v1/command-templates?os=${os}`, sig), [os])
  const [text, setText] = useState('')
  const [dlg, setDlg] = useState<Template | 'new' | null>(null)
  const [hint, setHint] = useState('')
  const all = useMemo(() => q.data?.templates ?? [], [q.data])
  const shown = useMemo(() => {
    const s = text.trim().toLowerCase()
    return s ? all.filter((c) => c.name.toLowerCase().includes(s) || c.command.toLowerCase().includes(s)) : all
  }, [all, text])

  function go(c: Template, run: boolean) {
    if (run && c.danger && !window.confirm(t('tpl.confirmRun', { name: c.name, command: c.command }))) return
    setHint(send(c.command.split('\n').join('; '), run) ? '' : t('tpl.needTerminal'))
  }
  async function remove(c: Template) {
    if (!window.confirm(t('tpl.confirmDelete', { name: c.name }))) return
    try { await api.del(`/api/v1/command-templates/${c.id}`) } catch (e) { setHint(why(e)); return }
    q.reload()
  }

  return (
    <aside aria-label={t('tpl.title')} className="rounded-control border border-line bg-elevated p-3">
      <div className="mb-2 flex items-center justify-between gap-2">
        <h3 className="text-[14px] font-medium">{t('tpl.title')}</h3>
        <GhostButton size="s" onClick={() => setDlg('new')}><Plus size={13} aria-hidden className="mr-1 inline" />{t('tpl.add')}</GhostButton>
      </div>
      <p className="mb-2 text-xs text-muted">{t(`tpl.note.${os}` as MsgKey)}</p>
      <input className={`${inputCls} mb-2 w-full text-[13px]`} value={text} onChange={(e) => setText(e.target.value)} placeholder={t('tpl.search')} aria-label={t('tpl.search')} />
      {hint && <p role="status" className="mb-2 text-xs text-amber">{hint}</p>}
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {q.data && all.length === 0 && <p className="py-2 text-[13px] text-muted">{t('tpl.empty')}</p>}
      {q.data && all.length > 0 && shown.length === 0 && <p className="py-2 text-[13px] text-muted">{t('tpl.noMatch')}</p>}
      <ul className="max-h-[52vh] divide-y divide-line/60 overflow-auto">
        {shown.map((c) => (
          <li key={c.id} className="py-2">
            <div className="flex items-start justify-between gap-2">
              <span className="text-[13px] font-medium">{c.name}{c.danger && <span className="ml-2 align-middle"><Chip tone="amber">{t('tpl.danger')}</Chip></span>}</span>
              <span className="flex shrink-0 gap-1">
                <button type="button" aria-label={`${t('tpl.edit')}: ${c.name}`} title={t('tpl.edit')} onClick={() => setDlg(c)} className="text-muted hover:text-fg"><Pencil size={13} aria-hidden /></button>
                <button type="button" aria-label={`${t('tpl.delete')}: ${c.name}`} title={t('tpl.delete')} onClick={() => void remove(c)} className="text-muted hover:text-red"><Trash2 size={13} aria-hidden /></button>
              </span>
            </div>
            {c.note && <p className="text-xs text-muted">{c.note}</p>}
            <pre className="mt-1 max-h-16 overflow-hidden whitespace-pre-wrap break-all font-mono text-[11px] text-muted">{c.command}</pre>
            <div className="mt-1 flex flex-wrap gap-x-3 text-xs">
              <button type="button" className="text-cyan hover:underline" aria-label={`${t('tpl.paste')}: ${c.name}`} onClick={() => go(c, false)}>{t('tpl.paste')}</button>
              <button type="button" className="text-cyan hover:underline" aria-label={`${t('tpl.run')}: ${c.name}`} onClick={() => go(c, true)}>{t('tpl.run')}</button>
            </div>
          </li>
        ))}
      </ul>
      {dlg && <TemplateDialog os={os} item={dlg === 'new' ? null : dlg} onClose={() => setDlg(null)} onDone={() => { setDlg(null); q.reload() }} />}
    </aside>
  )
}

function TemplateDialog({ os, item, onClose, onDone }: { os: 'linux' | 'windows'; item: Template | null; onClose: () => void; onDone: () => void }) {
  const [name, setName] = useState(item?.name ?? '')
  const [command, setCommand] = useState(item?.command ?? '')
  const [note, setNote] = useState(item?.note ?? '')
  const [danger, setDanger] = useState(item?.danger ?? false)
  const [busy, setBusy] = useState(false)
  const [error, setError] = useState('')
  async function save(e: React.FormEvent) {
    e.preventDefault()
    setBusy(true)
    setError('')
    try {
      const body = { name: name.trim(), command: command.trim(), note: note.trim(), danger }
      if (item) await api.patch(`/api/v1/command-templates/${item.id}`, body)
      else await api.post('/api/v1/command-templates', { ...body, os })
      onDone()
    } catch (err) {
      setError(why(err))
      setBusy(false)
    }
  }
  return (
    <Modal title={item ? t('tpl.dlg.edit', { name: item.name }) : t('tpl.dlg.new')} onClose={onClose} busy={busy}>
      <form onSubmit={save} className="space-y-3">
        <Field label={t('tpl.f.name')} htmlFor="tpl-name"><input id="tpl-name" className={inputCls} value={name} maxLength={80} onChange={(e) => setName(e.target.value)} data-autofocus /></Field>
        <Field label={t('tpl.f.command')} hint={t('tpl.f.commandHint')} htmlFor="tpl-command">
          <textarea id="tpl-command" className={`${inputCls} h-28 font-mono text-xs`} value={command} maxLength={2000} onChange={(e) => setCommand(e.target.value)} />
        </Field>
        <Field label={t('tpl.f.note')} htmlFor="tpl-note"><input id="tpl-note" className={inputCls} value={note} maxLength={200} onChange={(e) => setNote(e.target.value)} /></Field>
        <label className="flex cursor-pointer items-center gap-2 text-[13px]"><input type="checkbox" checked={danger} onChange={(e) => setDanger(e.target.checked)} />{t('tpl.f.danger')}</label>
        {error && <p role="alert" className="text-[13px] text-red">{error}</p>}
        <div className="flex gap-2">
          <PrimaryButton type="submit" size="m" disabled={busy || !name.trim() || !command.trim()}>{t('tpl.save')}</PrimaryButton>
          <GhostButton type="button" size="m" onClick={onClose} disabled={busy}>{t('common.cancel')}</GhostButton>
        </div>
      </form>
    </Modal>
  )
}
