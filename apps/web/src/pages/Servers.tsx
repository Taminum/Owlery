import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { useAuth } from '../lib/auth'
import { useModulesOff } from '../lib/modules'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import type { Server } from '../components/ServerParts'
import { ServerGroups } from '../components/ServerGroups'
import { LoadTable, ProtectTable } from '../components/ServerViews'
import { Journal } from '../components/SecurityJournal'
import { AddServer } from '../components/AddServer'
import { PrimaryButton, inputCls } from '../components/Modal'
import { Segmented } from '../components/ui'
import { BulkUpdate } from '../components/BulkUpdate'

type View = 'list' | 'load' | 'protect' | 'journal'
type Filter = 'all' | 'problems' | 'noagent'

/** One page for the machines: the same fleet as a list, by what it uses, by how it is protected, and the journal of what happened. */
export default function Servers() {
  const q = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 5_000)
  const { state } = useAuth()
  const owner = state.status === 'authed' && state.me.account.is_owner
  const off = useModulesOff()
  const [params, setParams] = useSearchParams()
  const [adding, setAdding] = useState(false)
  const [find, setFind] = useState('')
  const [filter, setFilter] = useState<Filter>('all')
  // The newest release, asked of the server (which asks GitHub at most every ten minutes).
  const latest = useLoad((sig) => api.get<{ version: string }>('/api/v1/agent/latest', sig), [], 600_000).data?.version ?? ''
  const all = q.data?.servers ?? []

  const secOn = !off.has('security')
  const wanted = params.get('view') as View | null
  const view: View = wanted && ['list', 'load', 'protect', 'journal'].includes(wanted) && (secOn || (wanted !== 'protect' && wanted !== 'journal')) ? wanted : 'list'
  const setView = (v: View) => setParams(v === 'list' ? {} : { view: v }, { replace: true })

  const needle = find.trim().toLowerCase()
  const matches = (s: Server) => !needle || s.name.toLowerCase().includes(needle) || s.addresses.some((a) => a.address.toLowerCase().includes(needle))
  const problem = (s: Server) => s.status === 'warn' || s.status === 'bad'
  const noAgent = (s: Server) => !s.agent
  const counts = { all: all.length, problems: all.filter(problem).length, noagent: all.filter(noAgent).length }
  const shown = all.filter((s) => matches(s) && (filter === 'all' || (filter === 'problems' ? problem(s) : noAgent(s))))

  const views: { value: View; label: string }[] = [
    { value: 'list', label: t('srv.view.machines') },
    { value: 'load', label: t('srv.view.load') },
    ...(secOn ? [{ value: 'protect' as const, label: t('srv.view.protect') }, { value: 'journal' as const, label: t('srv.view.journal') }] : []),
  ]
  return (
    <div className="space-y-5">
      <PageHead title={t('srv.title')} subtitle={t('srv.subtitle')}
        right={<div className="flex flex-wrap items-center gap-2">
          <BulkUpdate list={all} latest={latest} onProgress={q.reload} />
          {owner && <PrimaryButton onClick={() => setAdding(true)}>{t('srv.add')}</PrimaryButton>}
        </div>} />
      <div className="flex flex-wrap items-center gap-3">
        <Segmented label={t('srv.views')} value={view} onChange={setView} options={views} />
        {view !== 'journal' && all.length > 0 && (
          <>
            <input type="search" className={`${inputCls} !h-8 max-w-[260px] !text-[13px]`} aria-label={t('srv.find')} placeholder={t('srv.find')} value={find} onChange={(e) => setFind(e.target.value)} />
            <Segmented label={t('srv.filter')} value={filter} onChange={setFilter} options={[
              { value: 'all', label: t('srv.filter.all', { n: counts.all }) },
              { value: 'problems', label: t('srv.filter.problems', { n: counts.problems }) },
              { value: 'noagent', label: t('srv.filter.noagent', { n: counts.noagent }) },
            ]} />
          </>
        )}
      </div>
      {view !== 'journal' && q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {view !== 'journal' && !q.data && !q.error && <TableSkeleton />}
      {view !== 'journal' && q.data && all.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('srv.empty')}</p>}
      {adding && <AddServer onClose={() => { setAdding(false); q.reload() }} />}
      {view !== 'journal' && all.length > 0 && shown.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('srv.noMatch')}</p>}
      {view === 'list' && shown.length > 0 && <ServerGroups list={shown} latest={latest} />}
      {view === 'load' && shown.length > 0 && <LoadTable list={shown} />}
      {view === 'protect' && shown.length > 0 && <ProtectTable list={shown} />}
      {view === 'journal' && <Journal />}
    </div>
  )
}
