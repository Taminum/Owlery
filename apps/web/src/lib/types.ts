// Mirrors internal/demo/types.go. When the real API lands in M1+ the contract
// stays the same; `meta.demo` simply becomes false.
export type MetricKind = 'connection_count' | 'bytes'
export type OverviewState = 'ok' | 'no_data' | 'sync_pending'

export interface Gap { node_id: string; node_name: string; panel_id: string; from: string; to: string }
export interface Meta {
  demo: boolean
  state: OverviewState
  reason?: string
  generated_at: string
  from: string
  to: string
  granularity_seconds: number
  panel_ids: string[]
  node_ids: string[]
  coverage: { pct: number; gaps: Gap[] }
}
export interface Series { ts: number[]; v: number[] }
export interface Row {
  key: string
  label: string
  note?: string
  panel_id?: string
  panel_name?: string
  count: number
  share: number
  confidence?: 'high' | 'medium' | 'low'
  other?: boolean
}
export interface Overview {
  meta: Meta
  connections: { metric_kind: MetricKind; source: string; total: number; tcp: number; udp: number; delta_pct: number | null; series: Series }
  unique_hosts: { value: number; series: Series; source: string }
  unique_ips: { value: number; series: Series; source: string }
  nodes: { reporting: number; total: number }
  traffic: { metric_kind: MetricKind; source: string; unit: string; up_bytes: number; down_bytes: number; coverage_pct: number; series: { ts: number; up: number; down: number }[]; total_bytes?: number | null; total_series?: { ts: number; bytes: number }[]; counter_resets?: number }
  freshness: { last_event_at: string; lag_seconds: number; status: 'ok' | 'stale' }
  timeline: { ts: number; tcp: number; udp: number; gap: boolean }[]
  top_hosts: Row[]
  top_ips: Row[]
  top_ports: Row[]
  services: Row[]
  users: Row[]
  recent: { ts: string; panel_id: string; panel_name: string; node_name: string; user_label: string; protocol: 'tcp' | 'udp'; dest: string; dest_type: 'domain' | 'ip' }[]
}
export interface NodeInfo { id: string; panel_id: string; name: string; agent_status: 'ok' | 'lagging' | 'none'; lag_seconds: number }
export interface PanelInfo { id: string; name: string; nodes: NodeInfo[]; demo?: boolean; role?: string }

export type Role = 'viewer' | 'operator' | 'admin' | 'owner'
export interface Membership { panel_id: string; role: 'viewer' | 'operator' | 'admin' }
export interface Me {
  account: { id: string; username: string; is_owner: boolean }
  memberships: Membership[]
  csrf_token: string
  session_expires_at: string
  custom_ca_available: boolean
  mfa_enabled?: boolean
}
export interface MfaChallenge { mfa_required: true; mfa_token: string; expires_in: number }

export type CheckStatus = 'ok' | 'failed' | 'unsupported' | 'skipped'
export interface Check { name: string; status: CheckStatus; latency_ms: number; error_code?: string; required: boolean }
export interface Capabilities { nodes: boolean; users: boolean; system_stats: boolean; bandwidth_stats: boolean; metadata: boolean }
export interface ProbeSummary {
  reachable: boolean
  tls_ok: boolean
  authenticated: boolean
  required_ok: boolean
  api_version?: string
  capabilities: Capabilities
  node_count: number
  nodes_preview?: string[]
  checks: Check[]
}
export interface SyncOptions { nodes: boolean; users: boolean; stats: boolean }
export interface PanelDTO {
  id: string
  name: string
  base_url: string
  status: 'pending' | 'active' | 'disabled' | 'error'
  demo: boolean
  use_custom_ca: boolean
  sync_options: SyncOptions
  sync_interval_seconds: number
  retention_days: number
  api_version: string | null
  capabilities: Partial<Capabilities>
  last_probe_at: string | null
  last_probe: ProbeSummary | null
  last_sync_at: string | null
  last_sync_status: string | null
  next_sync_at: string | null
  consecutive_failures: number
  circuit_open_until: string | null
  node_count: number
  user_count: number
  token: 'configured' | 'none'
  role: Role | ''
  created_at: string
}
export interface SyncRun {
  id: string; panel_id: string; operation: string; trigger: string; status: string
  started_at: string; finished_at: string | null; error_code: string | null; detail: string | null
  stats: { added?: number; updated?: number; removed?: number; skipped?: number }
}
export interface AuditRow {
  id: string; actor_name: string | null; panel_id: string | null; action: string; object_type: string
  object_id: string | null; ts: string; request_id: string | null; metadata: Record<string, unknown>
}
export interface Agent {
  id: string; panel_id: string; node_id: string; node_name: string; name: string | null; kind: 'node' | 'router' | 'awg'; covers_user?: string | null
  status: 'enrolling' | 'active' | 'revoked'; agent_version: string | null; source_id: string | null
  last_seen: string | null; last_batch_at: string | null; last_event_at: string | null
  last_ack_seq: number; spool_bytes: number; dropped_total: number; parse_errors: number; events_total: number
  created_at: string
}
export interface AccountRow {
  id: string; username: string; is_owner: boolean; disabled: boolean
  last_login_at: string | null; created_at: string; memberships: Membership[]
}

// --- analyzer (connection_count only: accepted log lines, never bytes) ---
export interface AMeta {
  demo: boolean
  state: 'ok' | 'no_data'
  reason?: 'no_real_panels' | 'agents_not_connected' | 'no_events' | 'no_router' | 'no_counters'
  from: string
  to: string
  granularity_seconds: number
  panel_ids: string[]
  metric_kind: MetricKind
  source: string
  coverage: { nodes_total: number; nodes_with_agent: number }
}
export interface DestRow {
  key: string
  kind: 'domain' | 'ip' | 'service' | 'site' | 'category'
  origin?: string
  sources?: string[]
  service?: string
  confidence?: 'high' | 'medium' | 'low'
  connections: number
  share: number
  users: number
  nodes: number
  last_seen: string
  ports: number[]
  bytes: number | null; router_connections: number; category?: string; owner?: string; asn?: number
}
export interface DestResponse { meta: AMeta; group_by: 'host' | 'ip' | 'service' | 'site' | 'category'; rows: DestRow[]; groups: number; total_connections: number; limit: number; offset: number }
export interface UserRowA {
  key: string; panel_id: string; panel_name: string; label: string; note?: string
  connections: number; share: number; destinations: number; nodes: number; udp_share: number
  first_seen: string; last_seen: string
}
export interface UsersResponse { meta: AMeta; rows: UserRowA[]; total_connections: number }
export interface NamedCount { key: string; service?: string; count: number; share: number }
export interface UserDetailResponse {
  meta: AMeta; key: string; panel_id: string; panel_name: string; label: string; note?: string
  total: number; tcp: number; udp: number
  timeline: { ts: number; tcp: number; udp: number; gap: boolean }[]
  hosts: NamedCount[]; ports: NamedCount[]; nodes: NamedCount[]
}
export interface NodeRowA {
  node_id: string; name: string; panel_id: string; panel_name: string; agent: 'none' | 'live' | 'stale'
  last_seen: string | null; last_event_at: string | null
  connections: number; share: number; users: number; destinations: number; udp_share: number
}
export interface NodesResponse { meta: AMeta; rows: NodeRowA[]; total_connections: number }
export interface DeviceRowA {
  key: string; panel_id: string; panel_name: string; ip: string; name?: string
  connections: number; destinations: number; no_domain_share: number
  up_bytes: number; down_bytes: number; share: number; first_seen: string; last_seen: string
}
export interface DevicesResponse { meta: AMeta; rows: DeviceRowA[]; total_bytes: number }
export interface DeviceHostA { key: string; service?: string; connections: number; up_bytes: number; down_bytes: number; share: number }
export interface DeviceDetailResponse {
  meta: AMeta; key: string; panel_id: string; panel_name: string; ip: string; name?: string
  connections: number; up_bytes: number; down_bytes: number
  hosts: DeviceHostA[]; timeline: { ts: number; connections: number; up_bytes: number; down_bytes: number }[]
}
export interface TrafficNodeA {
  node_id: string; name: string; bytes: number; share: number; counter_resets: number; counter_bytes: number
  last_sample: string | null; samples: number
}
export interface TrafficUserA { panel_id: string; panel_name: string; label: string; note?: string; bytes: number; share: number; counter: 'lifetime' | 'period' }
export interface TrafficResponse {
  meta: AMeta; direction: 'total'; total_bytes: number; users_total_bytes: number; counter_resets: number; samples: number
  first_sample: string | null; last_sample: string | null
  timeline: { ts: number; bytes: number }[]; nodes: TrafficNodeA[]; users: TrafficUserA[]
}
export interface SiteRowA {
  site: string; service?: string; confidence?: string; category: string; classified: boolean; origin?: string; sources?: string[]
  connections: number; visits: number; share: number; users: number; devices: number; hosts: number
  bytes: number | null; router_connections: number; ru_zone: boolean; blocked: number; warp: number; first_seen: string; last_seen: string
}
export interface CategoryRowA { category: string; classified: boolean; sites: number; connections: number; visits: number; share: number; users: number; bytes: number | null; router_connections: number }
export interface SitesResponse { meta: AMeta; rows: SiteRowA[]; categories: CategoryRowA[]; groups: number; total_connections: number; limit: number; offset: number }
export interface SiteWhoA { kind: 'user' | 'device' | 'raw' | 'awg'; label: string; note?: string; panel_name: string; subject: string; connections: number; visits: number; bytes: number | null; first_seen: string; last_seen: string }
export interface SiteHostA { host: string; connections: number; share: number; users: number; bytes: number | null; router_connections: number; last_seen: string }
export interface SiteDetailResponse {
  meta: AMeta; site: string; service?: string; category: string; classified: boolean; origin?: string
  auto?: { model: string; reason: string; score: number; classified_at: string | null }
  connections: number; visits: number; users: number; bytes: number | null
  who: SiteWhoA[]; hosts: SiteHostA[]; timeline: { ts: number; connections: number }[]
}
export interface SubjectA { subject: string; kind: 'user' | 'raw' | 'device' | 'path' | 'awg'; label: string; panel_name: string; connections: number }
export interface SubjectsResponse { subjects: SubjectA[] }
export interface AlertRow { id: string; panel_id: string; panel_name: string; kind: string; label: string; detail: string; opened_at: string; last_seen_at: string; resolved_at: string | null }
export interface AlertsResponse { alerts: AlertRow[]; open: number }
export interface RuleRow { id: string; pattern: string; service: string; category: string; source: string; created_at: string | null }
export interface RulesResponse { rules: RuleRow[]; categories: string[]; can_edit: boolean }
export interface ActivityResponse { meta: AMeta; grid: number[][]; max: number; total: number }
export interface CountryRowA { code: string; name: string; connections: number; share: number; users: number; sites: number; bytes: number | null }
export interface CountriesResponse { meta: AMeta; rows: CountryRowA[]; located: number; no_ip: number; unknown: number; total_connections: number }
export interface LiveDeviceA { ip: string; name?: string; up_bps: number; down_bps: number; connections: number }
export interface LiveAgent {
  agent_id: string; name: string; panel_id: string; panel_name: string; live: boolean; age_ms: number
  connections: number; up_bps: number; down_bps: number; devices: LiveDeviceA[]
  series: { ts: number; up_bps: number; down_bps: number; connections: number }[]
}
export interface LiveResponse { agents: LiveAgent[]; has_router: boolean }
export interface ProbeTarget {
  id: string; panel_id: string; panel_name: string; name: string; host: string; port: number; mode: 'tcp' | 'tls'; sni?: string; enabled: boolean
  state: 'up' | 'down' | 'unknown'; last_at: string | null; last_error?: string; connect_ms: number | null; tls_ms: number | null
  samples_1h: number; loss_pct: number; p50_connect_ms: number | null; p50_tls_ms: number | null
  series: { ts: number; ms: number | null; samples: number; failed: number }[]
}
export interface ProbesResponse { targets: ProbeTarget[]; can_edit: boolean; max_per_panel: number }
export interface NetworkRowA { asn: number; org: string; connections: number; share: number; ips: number; bytes: number | null; examples: string[] }
export interface NetworksResponse { meta: AMeta; rows: NetworkRowA[]; ip_only: number; matched: number; unknown: number }
export interface AutoSettingsT { enabled: boolean; model: string; batch_size: number; daily_limit: number; updated_at: string }
export interface AutoRun { id: string; started_at: string; finished_at: string | null; model: string; state: 'running' | 'done' | 'failed'; requested: number; requests: number; tokens_in: number; tokens_out: number; error_code?: string }
export interface AutoQueue {
  counts: Record<string, number>; auto_rules: number; spent_today: number; requests_today: number; tokens_today: number
  last_success_at: string | null; last_error_code?: string; last_error_at?: string | null; backfill: 'idle' | 'running' | 'done'
}
export interface AutoStatus { settings: AutoSettingsT; key_present: boolean; running: boolean; categories: number; latest_run?: AutoRun; queue?: AutoQueue }
export interface AutoModels { models: { name: string; display_name: string }[]; error?: string }
export interface AutoItem { site: string; connections: number; picked_by: 'top' | 'random'; valid: boolean; undetermined: boolean; category?: string; service?: string; confidence: number; reason?: string; issue?: string }
export interface AutoDryRun {
  run: AutoRun | null; items: AutoItem[]
  summary: { total: number; valid: number; undetermined: number; invalid: number; with_service: number; low_confidence: number; by_category: Record<string, number>; issues: Record<string, number> }
}

export interface VPSAddress { address: string; kind: 'ipv4' | 'ipv6' | 'domain' }
export interface VPSLink { id: string; panel_id: string; node_id: string | null; provenance: string; created_at: string }
export interface VPS {
  id: string; name: string; origin: string; enabled: boolean; note: string
  created_at: string; updated_at: string; addresses: VPSAddress[]; links: VPSLink[]; can_edit: boolean
  discovery_scan?: boolean; discovery_scan_at?: string | null
  summary?: VPSSummary
  // What a person says about the machine (empty until filled in).
  roles?: ServerRole[]; os?: string; provider?: string; country?: string; city?: string; group?: string; tags?: string[]; purchased_on?: string | null
}

export type ServerRole = 'entry' | 'exit' | 'panel' | 'service' | 'workstation' | 'home' | 'hypervisor' | 'router'

export interface ServerNode { panel_id: string; panel_name: string; node_id: string; name: string; xray: string; users_online: number; online: boolean }
export interface ServerAlert { id: string; kind: string; subject: string; label: string; detail: string; opened_at: string; last_seen_at: string; resolved_at: string | null }
export interface VPSSummary {
  agent: 'none' | 'waiting' | 'online' | 'offline'
  fail2ban: { state: string; banned: number; total_banned: number; jails: number; observed_at: string | null }
}
export interface VPSList { items: VPS[]; can_create: boolean }

export interface SecAgent { id: string; status: string; agent_version: string | null; hostname: string | null; capabilities: string[]; last_seen: string | null; online: boolean }
export interface SecJail { name: string; currently_failed: number; total_failed: number; currently_banned: number; total_banned: number; banned_ips: string[] }
export interface SecListener { proto: string; addr: string; port: number; state?: string; process?: string; pid?: number; container?: string }
export interface SecCategory<T> {
  category: string; state: string; status?: string; observed_at: string | null; received_at: string | null; clock_skew_ms: number
  data: T | null; agent: SecAgent | null; manage?: SecManage; model?: SecFwModel
}
export interface SecEvent { id: string; category: string; type: string; severity: 'info' | 'warning' | 'critical'; source: string; observed_at: string; payload: Record<string, unknown> }

export interface Vantage { id: string; name?: string; independent: boolean }
export interface PublicPort {
  id: string; host: string; port: number; expected: boolean; source: 'manual' | 'local_listener' | 'discovered'; enabled: boolean
  last_checked_at: string | null; last_result: 'reachable' | 'refused' | 'timeout' | 'filtered_or_unknown' | 'error' | null
  last_error: string | null; last_ip: string | null; last_rtt_ms: number | null; changed_at: string | null
  vantage: Vantage | null
}
export interface PublicPortsResponse { items: PublicPort[]; vantage: Vantage; interval_minutes: number; coverage: { kind: string; discovery: string } }
export interface TLSObs {
  state?: string; ip?: string; sni?: string; name_checked?: boolean; version?: string; fingerprint?: string; subject?: string; issuer?: string
  dns_names?: string[] | null; not_before?: string | null; not_after?: string | null; days_left?: number; has_cert?: boolean; error?: string
}
export interface TLSEndpoint {
  id: string; host: string; port: number; sni: string; enabled: boolean; last_checked_at: string | null; last_state: string | null
  last_ip: string | null; last_fingerprint: string | null; last_not_after: string | null; last_obs: TLSObs
  vantage: Vantage | null; source?: 'manual' | 'auto'
}
export interface TLSResponse { items: TLSEndpoint[]; vantage: Vantage; interval_hours: number }

export interface JournalEvent extends SecEvent { vps_id: string; vps_name: string }
export interface SecSettings {
  agent_interval_seconds: number; stale_after_seconds: number; port_check_minutes: number; tls_check_hours: number
  tls_warn_days: number[]; retention_days: number; vantage: Vantage; discovery_scan: string
}

export interface SecManage { allowed: boolean; ready: boolean; reason?: string }
export interface SecCommand {
  id: string; vps_id: string; action: 'ban' | 'unban'; jail: string; ip: string; state: string; requested_at: string
  sent_at: string | null; deadline: string; finished_at: string | null; result_code: string | null; verified: boolean; final: boolean
}

export interface DnsCoverage {
  discovery: string; names_total: number; names_checked: number; names_dropped: number; types: string[] | null; resolvers: string[] | null
  questions: number; failures: number; unconfirmed: number; dnssec: string; authoritative_asked: number
}
export interface DnsAuth { ns: string; addr?: string; skipped?: string; answers?: Record<string, { outcome: string; values?: string[]; aa: boolean }> }
export interface DnsRun {
  id: string; trigger: string; started_at: string; finished_at: string | null; status: string
  coverage: DnsCoverage | Record<string, never>; auth: DnsAuth[]; mismatch: string[]; error: string | null
}
export interface DnsMap {
  id: string; domain: string; display: string; enabled: boolean; interval_hours: number; extra_names: string[]; use_ct: boolean
  created_at: string; last_run_at: string | null; next_run_at: string | null; last_status: string | null; baseline_done: boolean; last_run: DnsRun | null
}
export interface DnsView { server: string; outcome: string; values?: string[] }
export interface DnsRecord {
  name: string; type: string; result: string | null; values: string[]; ttl: number; confirmed: boolean; last_result: string; views: DnsView[]
  first_seen: string; last_seen: string | null; last_checked: string; last_changed: string | null; no_longer_observed: boolean
}
export interface DnsChange { id: string; name: string; type: string; kind: string; before: string[]; after: string[]; observed_at: string; volatile: boolean }
export interface DnsGraphNode { id: string; kind: 'name' | 'ip' | 'mail' | 'ns'; label: string; group?: string; provenance?: string }
export interface DnsGraphEdge { from: string; to: string; type: string; label?: string; unverified?: boolean; no_longer_observed?: boolean }
export interface DnsGraph { nodes: DnsGraphNode[]; edges: DnsGraphEdge[]; total_nodes: number; truncated: boolean; note: string }

export interface SecFwChain { name: string; type?: string; hook?: string; priority?: string; policy?: string; rules: string[] }
export interface SecFwTable { family: string; name: string; chains: SecFwChain[]; other?: string[] }
export interface SecFwModel { backend: string; tables: SecFwTable[]; rules: number }
export interface SecFwRef { id: string; observed_at: string; hash: string; backend: string }
export interface SecFwDiff {
  available: boolean; reason?: string; from?: SecFwRef; to?: SecFwRef; backend_changed?: boolean
  added?: number; removed?: number; truncated?: boolean; lines?: { op: string; text: string }[]
}
export interface SecFwSnapshot { id: string; observed_at: string; status: string; hash: string; backend: string }

export interface SecOverview {
  health: 'healthy' | 'attention' | 'unknown' | 'disabled'
  reasons: { code: string; detail?: string }[]
  agent: 'none' | 'waiting' | 'online' | 'offline'
  categories: Record<string, { state: string; observed_at: string | null }>
  checks: {
    ports_total: number; ports_unexpected: number; ports_down: number
    tls_total: number; tls_problems: number; tls_nearest_end: string | null; last_checked_at: string | null
  }
  last_event: SecEvent | null
  events_24h: number
}
export interface SecEventDetail { event: JournalEvent; related: JournalEvent[] }

export interface DigestSite { site: string; service?: string; category?: string; connections: number; users: number; first_seen: string }
export interface DigestDevice { panel_id: string; panel_name: string; ip: string; name: string; up_bytes: number; down_bytes: number; first_seen?: string }
export interface DigestResponse {
  from: string; to: string; new_sites: DigestSite[]; top_devices: DigestDevice[]; new_devices: DigestDevice[]; new_devices_note?: string
  security_events: { type: string; category: string; severity: 'info' | 'warning' | 'critical'; count: number }[]
  dns: { total: number; volatile: number; failed_checks: number } | null
  open_alerts: number; has_traffic: boolean; has_security: boolean
}
