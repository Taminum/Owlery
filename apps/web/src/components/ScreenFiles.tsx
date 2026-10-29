import { useEffect, useRef, useState } from 'react'
import { ArrowUp, Download, Folder, HardDrive, Upload, X } from 'lucide-react'
import { t } from '../i18n'
import { formatBytes } from '../lib/format'
import { joinPath, parentPath, type FsClient, type FsEntry } from '../lib/screenfs'

const btn = 'inline-flex h-7 shrink-0 items-center gap-1 rounded-control border border-line bg-elevated px-2.5 text-xs text-fg hover:border-cyan'

/** Saves a downloaded file through the browser. */
export function saveBlob(blob: Blob, name: string) {
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = name
  a.click()
  setTimeout(() => URL.revokeObjectURL(url), 10_000)
}

export function baseName(path: string): string {
  return path.slice(path.lastIndexOf('\\') + 1)
}

/** Uploads one file, asking before it replaces one that is there. */
export async function sendFile(fs: FsClient, file: File, dest: string, progress: (p: number) => void): Promise<void> {
  try {
    await fs.upload(file, dest, false, progress)
  } catch (e) {
    if (e instanceof Error && e.message === t('scr.exists.err') && window.confirm(t('scr.exists', { n: file.name }))) {
      await fs.upload(file, dest, true, progress)
      return
    }
    throw e
  }
}

/** The machine's files: folders to walk through, files to download, and a place to drop one. */
export function ScreenFiles({ fs, onClose }: { fs: FsClient; onClose: () => void }) {
  const [path, setPath] = useState('')
  const [entries, setEntries] = useState<FsEntry[]>([])
  const [home, setHome] = useState('')
  const [error, setError] = useState('')
  const [busy, setBusy] = useState('')
  const pick = useRef<HTMLInputElement>(null)

  async function open(p: string) {
    setError('')
    try {
      const r = await fs.list(p)
      setPath(r.path)
      setEntries(r.entries)
      if (r.home) setHome(r.home)
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e))
    }
  }
  useEffect(() => {
    let live = true
    fs.list('').then((r) => { if (live) { setPath(r.path); setEntries(r.entries); if (r.home) setHome(r.home) } })
      .catch((e: unknown) => { if (live) setError(e instanceof Error ? e.message : String(e)) })
    return () => { live = false }
  }, [fs])

  async function download(e: FsEntry) {
    const full = joinPath(path, e.n)
    setBusy(t('scr.progress', { n: e.n, p: '0' }))
    try {
      saveBlob(await fs.download(full, (p) => setBusy(t('scr.progress', { n: e.n, p: String(p) }))), e.n)
      setBusy('')
    } catch (err) {
      setBusy('')
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  async function upload(f: File) {
    setBusy(t('scr.progress', { n: f.name, p: '0' }))
    try {
      await sendFile(fs, f, joinPath(path, f.name), (p) => setBusy(t('scr.progress', { n: f.name, p: String(p) })))
      setBusy('')
      await open(path)
    } catch (err) {
      setBusy('')
      setError(err instanceof Error ? err.message : String(err))
    }
  }

  return (
    <div className="absolute inset-x-4 bottom-4 top-14 z-10 flex flex-col rounded-control border border-line bg-surface shadow-lg" role="dialog" aria-label={t('scr.files')}>
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <span className="text-xs font-semibold text-cyan">{t('scr.files')}</span>
        <button type="button" className={btn} onClick={() => void open('')}><HardDrive size={13} aria-hidden /> {t('scr.drives')}</button>
        {home && <button type="button" className={btn} onClick={() => void open(home)}><Download size={13} aria-hidden /> {t('scr.downloads')}</button>}
        <button type="button" className={btn} disabled={!path} onClick={() => void open(parentPath(path))}><ArrowUp size={13} aria-hidden /> {t('scr.up')}</button>
        <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted" title={path}>{path || t('scr.drives')}</span>
        <button type="button" className={btn} disabled={!path} onClick={() => pick.current?.click()}><Upload size={13} aria-hidden /> {t('scr.uploadHere')}</button>
        <input ref={pick} type="file" className="hidden" onChange={(e) => { const f = e.target.files?.[0]; e.target.value = ''; if (f) void upload(f) }} />
        <button type="button" className="h-7 rounded-control border border-line px-2 text-fg hover:border-red" aria-label={t('scr.close')} onClick={onClose}><X size={14} aria-hidden /></button>
      </div>
      {(busy || error) && <p className={`px-3 py-1.5 text-xs ${error ? 'text-red' : 'text-muted'}`} role={error ? 'alert' : 'status'}>{error || busy}</p>}
      <ul className="min-h-0 flex-1 divide-y divide-line overflow-auto text-[13px]">
        {entries.length === 0 && !error && <li className="px-3 py-3 text-muted">{t('scr.fsEmpty')}</li>}
        {entries.map((e) => (
          <li key={e.n} className="flex items-center gap-3 px-3 py-1.5 hover:bg-elevated">
            {e.d ? <Folder size={15} className="shrink-0 text-amber" aria-hidden /> : <span className="w-[15px] shrink-0" />}
            {e.d
              ? <button type="button" className="min-w-0 flex-1 truncate text-left text-fg" onClick={() => void open(joinPath(path, e.n))}>{e.n}</button>
              : <span className="min-w-0 flex-1 truncate">{e.n}</span>}
            {!e.d && <span className="tnum shrink-0 text-xs text-muted">{formatBytes(e.s ?? 0)}</span>}
            {!e.d && <button type="button" className={btn} onClick={() => void download(e)}><Download size={13} aria-hidden /> {t('scr.download')}</button>}
          </li>
        ))}
      </ul>
    </div>
  )
}
