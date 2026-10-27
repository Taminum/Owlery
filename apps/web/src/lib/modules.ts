import { useEffect, useSyncExternalStore } from 'react'
import { api } from './api'

export type ModuleId = 'remnawave' | 'awg' | 'security' | 'intel' | 'billing'
export const MODULES: ModuleId[] = ['remnawave', 'awg', 'security', 'intel', 'billing']

interface ModuleState { id: ModuleId; enabled: boolean }

// Which optional parts are on. Until the server answers everything counts as on, so the menu never flickers away.
let off = new Set<ModuleId>()
let loaded = false
let loading = false
const listeners = new Set<() => void>()
const emit = () => listeners.forEach((l) => l())

function apply(list: ModuleState[]) {
  off = new Set(list.filter((m) => !m.enabled).map((m) => m.id))
  loaded = true
  emit()
}

function load() {
  if (loading || loaded) return
  loading = true
  api.get<{ modules: ModuleState[] }>('/api/v1/modules')
    .then((r) => apply(r.modules))
    .catch(() => {})
    .finally(() => { loading = false })
}

/** The modules that are off right now; empty while unknown. */
export function useModulesOff(): Set<ModuleId> {
  useEffect(load, [])
  return useSyncExternalStore((cb) => { listeners.add(cb); return () => listeners.delete(cb) }, () => off)
}

export async function setModule(id: ModuleId, enabled: boolean): Promise<void> {
  const r = await api.put<{ modules: ModuleState[] }>(`/api/v1/modules/${id}`, { enabled })
  apply(r.modules)
}
