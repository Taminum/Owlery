import { useState } from 'react'
import { Outlet } from 'react-router-dom'
import { FlaskConical } from 'lucide-react'
import { t } from '../i18n'
import { useAuth } from '../lib/auth'
import { useFilters } from '../hooks/useFilters'
import { useOverview, usePanels } from '../hooks/useData'
import { DEFAULT_FILTERS } from '../lib/filters'
import type { AppContext } from '../lib/context'
import Login from '../pages/Login'
import { PAGE_WIDTH } from '../lib/layout'
import { Sidebar } from './Sidebar'
import { TopBar } from './TopBar'
import { FailureState, OverviewSkeleton } from './States'
import { Mascot } from '../ember/Mascot'
import { BusyBar } from './BusyBar'

/** Nothing of the app is rendered, and no data is requested, until there is a session. */
export function Layout() {
  const { state } = useAuth()
  if (state.status === 'loading') {
    return <div className="grid min-h-full place-items-center text-[14px] text-muted" role="status">{t('auth.loading')}</div>
  }
  if (state.status === 'anon') return <Login expired={state.expired} />
  return <Shell />
}

function Shell() {
  const [menu, setMenu] = useState(false)
  const { panels, failure: panelsFailure, retry } = usePanels()
  const { filters, update, demoState } = useFilters(panels)
  const overview = useOverview(filters, demoState)

  const ctx: AppContext | null =
    panels && filters
      ? { panels, filters, update, overview, reloadScope: retry, reset: () => update(() => ({ ...DEFAULT_FILTERS, tz: filters.tz })) }
      : null

  // The banner describes the data on screen: shown only while synthetic numbers are displayed.
  const showingDemo = overview.data?.meta.demo === true

  return (
    <div className="flex min-h-full">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-3 focus:top-3 focus:z-50 focus:rounded-control focus:bg-elevated focus:px-3 focus:py-2">{t('a11y.skip')}</a>
      <Sidebar open={menu} onClose={() => setMenu(false)} />
      <div className="flex min-w-0 flex-1 flex-col">
        {showingDemo && (
          <div role="note" className="flex items-center justify-center gap-2 border-b border-amber/30 bg-amber/10 px-4 py-1.5 text-center text-xs text-amber">
            <FlaskConical size={14} className="shrink-0" aria-hidden />
            <span><strong className="font-semibold tracking-wide">{t('demo.banner')}.</strong> {t('demo.bannerText')}</span>
          </div>
        )}
        {ctx && <TopBar filters={ctx.filters} panels={ctx.panels} update={ctx.update} onRefresh={overview.refresh} loading={overview.loading} onMenu={() => setMenu(true)} />}
        <main id="main" className={`${PAGE_WIDTH} flex-1 py-5`}>
          {ctx ? <Outlet context={ctx} /> : panelsFailure ? <FailureState failure={panelsFailure} onRetry={retry} onReset={retry} /> : <OverviewSkeleton />}
        </main>
      </div>
      <BusyBar />
      <Mascot />
    </div>
  )
}
