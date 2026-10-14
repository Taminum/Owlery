import { useOutletContext } from 'react-router-dom'
import type { useOverview } from '../hooks/useData'
import type { Filters } from './filters'
import type { PanelInfo } from './types'

export interface AppContext {
  panels: PanelInfo[]
  filters: Filters
  update: (patch: Partial<Filters> | ((f: Filters) => Filters)) => void
  overview: ReturnType<typeof useOverview>
  reloadScope: () => void
  reset: () => void
}

export const useApp = () => useOutletContext<AppContext>()
