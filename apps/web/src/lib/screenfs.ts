// File transfer over the screen session's channel to the machine's helper (see package remotehelper, fs_windows.go).
// Every request carries an id so that several can be in flight; a download arrives in chunks, an upload leaves in chunks.

export const MSG_FS_LIST = 12
export const MSG_FS_GET = 13
export const MSG_FS_PUT_BEGIN = 14
export const MSG_FS_PUT_DATA = 15
export const MSG_FS_PUT_END = 16
export const MSG_FS_CANCEL = 17
const MSG_FS_RESULT = 18
const MSG_FS_DATA = 19
const MSG_FS_END = 20

const CHUNK = 48 << 10

export type FsEntry = { n: string; d?: boolean; s?: number; t?: number }
export type FsList = { path: string; entries: FsEntry[]; home: string }
type Result = { id: number; ok?: boolean; error?: string; path?: string; home?: string; entries?: FsEntry[]; size?: number }

type Pending =
  | { kind: 'list'; resolve: (v: FsList) => void; reject: (e: Error) => void }
  | { kind: 'get'; resolve: (v: Blob) => void; reject: (e: Error) => void; chunks: Uint8Array[]; size: number; got: number; progress?: (p: number) => void }
  | { kind: 'put'; resolve: () => void; reject: (e: Error) => void; started: (r: Result) => void }

const enc = new TextEncoder()
const dec = new TextDecoder()

/** The folder separator of a Windows path, so that a name can be put after a folder. */
export function joinPath(dir: string, name: string): string {
  return dir.endsWith('\\') ? dir + name : `${dir}\\${name}`
}

export function parentPath(path: string): string {
  const trimmed = path.replace(/\\+$/, '')
  const i = trimmed.lastIndexOf('\\')
  if (i < 0) return ''
  const up = trimmed.slice(0, i)
  return up.includes('\\') ? up : `${up}\\`
}

export class FsClient {
  private next = 1
  private pending = new Map<number, Pending>()

  constructor(
    private send: (type: number, payload: Uint8Array) => void,
    private buffered: () => number,
  ) {}

  private json(type: number, v: object) { this.send(type, enc.encode(JSON.stringify(v))) }

  /** Takes a message from the machine if it belongs to a transfer; says whether it did. */
  handle(type: number, p: Uint8Array): boolean {
    if (type === MSG_FS_RESULT) {
      const r = JSON.parse(dec.decode(p)) as Result
      const w = this.pending.get(r.id)
      if (!w) return true
      if (w.kind === 'list') {
        this.pending.delete(r.id)
        if (r.ok) w.resolve({ path: r.path ?? '', entries: r.entries ?? [], home: r.home ?? '' })
        else w.reject(new Error(r.error || 'error'))
      } else if (w.kind === 'get') {
        if (!r.ok) { this.pending.delete(r.id); w.reject(new Error(r.error || 'error')) } else w.size = r.size ?? 0
      } else {
        w.started(r)
      }
      return true
    }
    if (type === MSG_FS_DATA && p.length > 4) {
      const id = new DataView(p.buffer, p.byteOffset, p.byteLength).getUint32(0)
      const w = this.pending.get(id)
      if (w?.kind === 'get') {
        w.chunks.push(p.slice(4))
        w.got += p.length - 4
        if (w.size > 0) w.progress?.(Math.min(100, Math.round((w.got / w.size) * 100)))
      }
      return true
    }
    if (type === MSG_FS_END) {
      const r = JSON.parse(dec.decode(p)) as Result
      const w = this.pending.get(r.id)
      if (!w) return true
      this.pending.delete(r.id)
      if (!r.ok) w.reject(new Error(r.error || 'error'))
      else if (w.kind === 'get') w.resolve(new Blob(w.chunks as BlobPart[]))
      else if (w.kind === 'put') w.resolve()
      return true
    }
    return false
  }

  list(path: string): Promise<FsList> {
    const id = this.next++
    return new Promise((resolve, reject) => {
      this.pending.set(id, { kind: 'list', resolve, reject })
      this.json(MSG_FS_LIST, { id, path })
    })
  }

  download(path: string, progress?: (p: number) => void): Promise<Blob> {
    const id = this.next++
    return new Promise((resolve, reject) => {
      this.pending.set(id, { kind: 'get', resolve, reject, chunks: [], size: 0, got: 0, progress })
      this.json(MSG_FS_GET, { id, path })
    })
  }

  /** Sends a file to the machine. The promise fails with the message "файл уже есть" when the name is taken and overwrite is off. */
  upload(file: File, dest: string, overwrite: boolean, progress?: (p: number) => void): Promise<void> {
    const id = this.next++
    return new Promise<void>((resolve, reject) => {
      const started = async (r: Result) => {
        if (!r.ok) { this.pending.delete(id); reject(new Error(r.error || 'error')); return }
        try {
          for (let off = 0; off < file.size; off += CHUNK) {
            while (this.buffered() > 1 << 20) await new Promise((x) => setTimeout(x, 20))
            const body = new Uint8Array(await file.slice(off, off + CHUNK).arrayBuffer())
            const msg = new Uint8Array(4 + body.length)
            new DataView(msg.buffer).setUint32(0, id)
            msg.set(body, 4)
            this.send(MSG_FS_PUT_DATA, msg)
            progress?.(Math.min(100, Math.round(((off + body.length) / file.size) * 100)))
          }
          this.json(MSG_FS_PUT_END, { id })
        } catch (e) {
          this.pending.delete(id)
          reject(e instanceof Error ? e : new Error('error'))
        }
      }
      this.pending.set(id, { kind: 'put', resolve, reject, started: (r) => void started(r) })
      this.json(MSG_FS_PUT_BEGIN, { id, path: dest, size: file.size, overwrite })
    })
  }

  /** Ends everything that is still waiting, when the session ends. */
  close() {
    for (const [, w] of this.pending) w.reject(new Error('closed'))
    this.pending.clear()
  }
}
