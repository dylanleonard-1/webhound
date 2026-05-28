'use client'

// Team Management — staff roles, recent logins, force-logout review, and
// the Redis-backed maintenance-mode toggle. Role changes + maintenance
// toggle require SUPER_ADMIN.

import { useCallback, useEffect, useState } from 'react'
import {
  UserCog, Loader2, ShieldHalf, Wrench, Power, Activity,
} from 'lucide-react'
import {
  api, type StaffMember, type LoginRow, type DenylistedUser, type MaintenanceState,
} from '@/lib/api'
import { useInternalMe } from '../layout'

const LIME = '#8BFF3E'
const ROLE_RANK: Record<string, number> = {
  none: 0, read_only: 10, billing: 20, support: 20, developer: 20,
  analyst: 30, admin: 90, super_admin: 100,
}

const ROLES = ['none', 'read_only', 'billing', 'support', 'developer', 'analyst', 'admin', 'super_admin'] as const
const ROLE_COLOR: Record<string, string> = {
  super_admin: '#a855f7', admin: '#ef4444', analyst: '#f97316',
  developer: '#3b82f6', support: '#06b6d4', billing: '#06b6d4',
  read_only: '#6b7280', none: '#374151',
}

function RolePill({ role }: { role: string }) {
  const c = ROLE_COLOR[role] ?? '#6b7280'
  return (
    <span className="text-[10px] font-bold uppercase tracking-wider px-1.5 py-0.5 rounded"
          style={{ background: `${c}1a`, color: c, border: `1px solid ${c}33` }}>{role.replace('_', ' ')}</span>
  )
}

export default function TeamPage() {
  const me = useInternalMe()
  const isSuper = (ROLE_RANK[me?.role ?? 'none'] ?? 0) >= ROLE_RANK.super_admin

  const [staff, setStaff] = useState<StaffMember[]>([])
  const [forceLoggedOutCount, setFLO] = useState(0)
  const [logins, setLogins] = useState<LoginRow[]>([])
  const [revoked, setRevoked] = useState<DenylistedUser[]>([])
  const [maint, setMaint] = useState<MaintenanceState | null>(null)
  const [busy, setBusy] = useState<string | null>(null)

  const load = useCallback(async () => {
    const [t, s, m] = await Promise.allSettled([
      api.internal.team(),
      api.internal.teamSessions(72),
      api.internal.maintenanceStatus(),
    ])
    if (t.status === 'fulfilled') { setStaff(t.value.staff); setFLO(t.value.force_logged_out_count) }
    if (s.status === 'fulfilled') { setLogins(s.value.recent_logins); setRevoked(s.value.force_logged_out) }
    if (m.status === 'fulfilled') setMaint(m.value)
  }, [])
  useEffect(() => { load() }, [load])

  const changeRole = async (user_id: string, role: string) => {
    if (!confirm(`Change role to ${role}?`)) return
    setBusy(user_id)
    try { await api.internal.setUserRole(user_id, role); await load() } finally { setBusy(null) }
  }

  const toggleMaint = async () => {
    if (!maint) return
    const next = !maint.active
    const reason = next ? (window.prompt('Maintenance reason (optional):') ?? '') : ''
    setBusy('maint')
    try { await api.internal.setMaintenance(next, reason || null); await load() } finally { setBusy(null) }
  }

  return (
    <div className="space-y-5">
      <div className="flex items-center gap-2">
        <UserCog className="w-5 h-5" style={{ color: LIME }} />
        <h1 className="text-[19px] font-bold text-white">Team &amp; Sessions</h1>
      </div>

      {/* Maintenance mode card */}
      <div className="rounded-xl p-4"
           style={{ background: maint?.active ? 'rgba(245,158,11,0.06)' : 'rgba(255,255,255,0.02)',
                    border: `1px solid ${maint?.active ? 'rgba(245,158,11,0.3)' : 'rgba(255,255,255,0.07)'}` }}>
        <div className="flex items-center gap-3">
          <Wrench className="w-4 h-4" style={{ color: maint?.active ? '#f59e0b' : 'rgba(255,255,255,0.5)' }} />
          <div className="flex-1">
            <div className="text-[13px] font-semibold text-white">
              Maintenance mode {maint?.active ? <span style={{ color: '#f59e0b' }}>· ENGAGED</span> : <span className="text-white/40">· off</span>}
            </div>
            <div className="text-[11px] mt-0.5 text-white/55">
              When engaged, /scan-jobs, /websites and /scan-schedules return 503 so staff can do infra work without losing queued scans.
              {maint?.reason && <span className="block mt-0.5">Reason: <span className="text-white/80">{maint.reason}</span></span>}
            </div>
          </div>
          {isSuper && (
            <button disabled={busy !== null} onClick={toggleMaint}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-[12px] font-semibold disabled:opacity-40"
                    style={maint?.active
                      ? { background: 'rgba(139,255,62,0.1)', color: LIME, border: '1px solid rgba(139,255,62,0.3)' }
                      : { background: 'rgba(245,158,11,0.1)', color: '#f59e0b', border: '1px solid rgba(245,158,11,0.3)' }}>
              {busy === 'maint' ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Power className="w-3.5 h-3.5" />}
              {maint?.active ? 'Disengage' : 'Engage'}
            </button>
          )}
        </div>
      </div>

      {/* Staff roster */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <ShieldHalf className="w-4 h-4" style={{ color: LIME }} />
          <span className="text-[13px] font-semibold text-white">Staff ({staff.length})</span>
          {forceLoggedOutCount > 0 && (
            <span className="text-[11px] text-orange-400">· {forceLoggedOutCount} session{forceLoggedOutCount !== 1 ? 's' : ''} revoked</span>
          )}
        </div>
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
                <th className="font-semibold px-3 py-2.5">Email</th>
                <th className="font-semibold px-3 py-2.5">Role</th>
                <th className="font-semibold px-3 py-2.5">Last login</th>
                <th className="font-semibold px-3 py-2.5">Active</th>
                {isSuper && <th className="font-semibold px-3 py-2.5">Change role</th>}
              </tr>
            </thead>
            <tbody>
              {staff.length === 0 ? (
                <tr><td colSpan={5} className="px-3 py-6 text-center text-white/35">No staff yet.</td></tr>
              ) : staff.map(s => (
                <tr key={s.id} className="border-t border-white/[0.04]">
                  <td className="px-3 py-2 text-white/90">{s.email}</td>
                  <td className="px-3 py-2"><RolePill role={s.admin_role} /></td>
                  <td className="px-3 py-2 text-white/55">{s.last_login_at ? new Date(s.last_login_at).toLocaleString() : '—'}</td>
                  <td className="px-3 py-2">{s.is_active ? <span className="text-[11px]" style={{ color: LIME }}>yes</span> : <span className="text-[11px] text-red-400">no</span>}</td>
                  {isSuper && (
                    <td className="px-3 py-2">
                      <select defaultValue={s.admin_role} disabled={busy === s.id || s.id === me?.id}
                              onChange={e => changeRole(s.id, e.target.value)}
                              className="px-2 py-1 rounded text-[11px] text-white/85 outline-none disabled:opacity-40"
                              style={{ background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.08)' }}>
                        {ROLES.map(r => <option key={r} value={r} className="bg-[#0b0f17]">{r}</option>)}
                      </select>
                    </td>
                  )}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Recent logins */}
      <div className="space-y-2">
        <div className="flex items-center gap-2">
          <Activity className="w-4 h-4" style={{ color: LIME }} />
          <span className="text-[13px] font-semibold text-white">Recent logins (72h, {logins.length})</span>
        </div>
        <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(255,255,255,0.07)' }}>
          <table className="w-full text-[12px]">
            <thead>
              <tr className="text-left" style={{ background: 'rgba(255,255,255,0.02)', color: 'rgba(255,255,255,0.4)' }}>
                <th className="font-semibold px-3 py-2.5">Email</th>
                <th className="font-semibold px-3 py-2.5">Role</th>
                <th className="font-semibold px-3 py-2.5">Last login</th>
              </tr>
            </thead>
            <tbody>
              {logins.length === 0 ? (
                <tr><td colSpan={3} className="px-3 py-6 text-center text-white/35">No logins in the last 72h.</td></tr>
              ) : logins.slice(0, 50).map(l => (
                <tr key={l.id} className="border-t border-white/[0.04]">
                  <td className="px-3 py-2 text-white/85">{l.email}</td>
                  <td className="px-3 py-2"><RolePill role={l.admin_role} /></td>
                  <td className="px-3 py-2 text-white/55">{l.last_login_at ? new Date(l.last_login_at).toLocaleString() : '—'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {revoked.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2">
            <Power className="w-4 h-4 text-orange-400" />
            <span className="text-[13px] font-semibold text-white">Revoked sessions ({revoked.length})</span>
            <span className="text-[11px] text-white/40">force-logged-out, denylist still active</span>
          </div>
          <div className="rounded-xl overflow-hidden" style={{ border: '1px solid rgba(245,158,11,0.2)' }}>
            <table className="w-full text-[12px]">
              <tbody>
                {revoked.map(r => (
                  <tr key={r.id} className="border-t border-white/[0.04]">
                    <td className="px-3 py-2 text-white/85">{r.email}</td>
                    <td className="px-3 py-2"><RolePill role={r.admin_role} /></td>
                    <td className="px-3 py-2 text-[11px] text-white/45">{r.is_active ? 'account active (force-logout only)' : 'account also suspended'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
