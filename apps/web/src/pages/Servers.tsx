import { useState } from 'react'
import { t } from '../i18n'
import { api } from '../lib/api'
import { useLoad } from '../hooks/useLoad'
import { useAuth } from '../lib/auth'
import { PageHead, TableSkeleton } from '../components/Analyzer'
import type { Server } from '../components/ServerParts'
import { ServerGroups } from '../components/ServerGroups'
import { AddServer } from '../components/AddServer'
import { PrimaryButton } from '../components/Modal'
import { BulkUpdate } from '../components/BulkUpdate'

export default function Servers() {
  const q = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 5_000)
  const { state } = useAuth()
  const owner = state.status === 'authed' && state.me.account.is_owner
  const [adding, setAdding] = useState(false)
  // The newest release, asked of the server (which asks GitHub at most every ten minutes).
  const latest = useLoad((sig) => api.get<{ version: string }>('/api/v1/agent/latest', sig), [], 600_000).data?.version ?? ''
  const list = q.data?.servers ?? []
  return (
    <div className="space-y-5">
      <PageHead title={t('srv.title')} subtitle={t('srv.subtitle')}
        right={<div className="flex flex-wrap items-center gap-2">
          <BulkUpdate list={list} latest={latest} onProgress={q.reload} />
          {owner && <PrimaryButton onClick={() => setAdding(true)}>{t('srv.add')}</PrimaryButton>}
        </div>} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && list.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('srv.empty')}</p>}
      {adding && <AddServer onClose={() => { setAdding(false); q.reload() }} />}
      {list.length > 0 && <ServerGroups list={list} latest={latest} />}
    </div>
  )
}
