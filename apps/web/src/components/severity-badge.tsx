import { cn } from '@/lib/utils'

type Severity  = 'critical' | 'high' | 'medium' | 'low' | 'info'
type ScanStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
type RiskLevel  = 'critical' | 'high' | 'medium' | 'low' | 'none'

// ── Shared pill ───────────────────────────────────────────────────────────────

function Pill({ label, bg, border, color, className }: {
  label: string; bg: string; border: string; color: string; className?: string
}) {
  return (
    <span
      className={cn('inline-flex items-center px-2 py-0.5 rounded-[5px] text-[10px] font-black font-mono uppercase tracking-wider border', className)}
      style={{ background: bg, borderColor: border, color }}
    >
      {label}
    </span>
  )
}

// ── Severity badge ────────────────────────────────────────────────────────────

const SEV: Record<Severity, { bg: string; border: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.3)',   color: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.1)',  border: 'rgba(249,115,22,0.3)',  color: '#f97316' },
  medium:   { bg: 'rgba(234,179,8,0.1)',   border: 'rgba(234,179,8,0.3)',   color: '#eab308' },
  low:      { bg: 'rgba(59,130,246,0.1)',  border: 'rgba(59,130,246,0.3)',  color: '#3b82f6' },
  info:     { bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.2)', color: '#9ca3af' },
}

export function SeverityBadge({ severity, className }: { severity: Severity; className?: string }) {
  const s = SEV[severity]
  return <Pill label={severity} bg={s.bg} border={s.border} color={s.color} className={className} />
}

// ── Status badge ──────────────────────────────────────────────────────────────

const ST: Record<ScanStatus, { bg: string; border: string; color: string }> = {
  queued:    { bg: 'rgba(107,114,128,0.1)', border: 'rgba(107,114,128,0.2)', color: '#9ca3af'  },
  running:   { bg: 'rgba(79,156,249,0.1)',  border: 'rgba(79,156,249,0.25)', color: '#4F9CF9'  },
  completed: { bg: 'rgba(139,255,62,0.08)', border: 'rgba(139,255,62,0.22)', color: '#8BFF3E'  },
  failed:    { bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.25)',  color: '#ef4444'  },
  cancelled: { bg: 'rgba(107,114,128,0.07)',border: 'rgba(107,114,128,0.15)',color: '#6b7280'  },
}

export function StatusBadge({ status, className }: { status: ScanStatus; className?: string }) {
  const s = ST[status]
  return <Pill label={status} bg={s.bg} border={s.border} color={s.color} className={className} />
}

// ── Risk badge ────────────────────────────────────────────────────────────────

const RL: Record<RiskLevel, { bg: string; border: string; color: string }> = {
  critical: { bg: 'rgba(239,68,68,0.1)',   border: 'rgba(239,68,68,0.3)',   color: '#ef4444' },
  high:     { bg: 'rgba(249,115,22,0.1)',  border: 'rgba(249,115,22,0.3)',  color: '#f97316' },
  medium:   { bg: 'rgba(234,179,8,0.1)',   border: 'rgba(234,179,8,0.3)',   color: '#eab308' },
  low:      { bg: 'rgba(59,130,246,0.1)',  border: 'rgba(59,130,246,0.3)',  color: '#3b82f6' },
  none:     { bg: 'rgba(139,255,62,0.08)', border: 'rgba(139,255,62,0.22)', color: '#8BFF3E' },
}

export function RiskBadge({ risk, className }: { risk: RiskLevel; className?: string }) {
  const s = RL[risk]
  return <Pill label={risk === 'none' ? 'clean' : risk} bg={s.bg} border={s.border} color={s.color} className={className} />
}
