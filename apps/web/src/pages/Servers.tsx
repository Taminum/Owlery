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

export default function Servers() {
  const q = useLoad((sig) => api.get<{ servers: Server[] }>('/api/v1/servers', sig), [], 10_000)
  const { state } = useAuth()
  const owner = state.status === 'authed' && state.me.account.is_owner
  const [adding, setAdding] = useState(false)
  const list = q.data?.servers ?? []
  return (
    <div className="space-y-5">
      <PageHead title={t('srv.title')} subtitle={t('srv.subtitle')}
        right={owner ? <PrimaryButton onClick={() => setAdding(true)}>{t('srv.add')}</PrimaryButton> : undefined} />
      {q.error && <p role="alert" className="text-[13px] text-red">{q.error}</p>}
      {!q.data && !q.error && <TableSkeleton />}
      {q.data && list.length === 0 && <p className="py-10 text-center text-[13px] text-muted">{t('srv.empty')}</p>}
      {adding && <AddServer onClose={() => { setAdding(false); q.reload() }} />}
      {list.length > 0 && <ServerGroups list={list} />}
    </div>
  )
}
