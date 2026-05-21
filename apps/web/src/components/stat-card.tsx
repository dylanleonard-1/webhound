import Link from 'next/link'
import { ArrowRight, TrendingUp, TrendingDown, type LucideIcon } from 'lucide-react'
import { cn } from '@/lib/utils'

interface StatCardProps {
  title: string
  value: string | number
  icon: LucideIcon
  accent?: 'green' | 'blue' | 'orange' | 'red' | 'violet' | 'default'
  href?: string
  trend?: { value: number; label: string }
  subtitle?: string
}

const ACCENT: Record<NonNullable<StatCardProps['accent']>, {
  icon: string; iconBg: string; value: string; glow: string
}> = {
  green:   { icon: '#8BFF3E',  iconBg: 'rgba(139,255,62,0.1)',   value: '#8BFF3E',  glow: 'rgba(139,255,62,0.08)' },
  blue:    { icon: '#4F9CF9',  iconBg: 'rgba(79,156,249,0.1)',   value: '#4F9CF9',  glow: 'rgba(79,156,249,0.07)' },
  orange:  { icon: '#f97316',  iconBg: 'rgba(249,115,22,0.1)',   value: '#f97316',  glow: 'rgba(249,115,22,0.07)' },
  red:     { icon: '#ef4444',  iconBg: 'rgba(239,68,68,0.1)',    value: '#ef4444',  glow: 'rgba(239,68,68,0.07)'  },
  violet:  { icon: '#a78bfa',  iconBg: 'rgba(167,139,250,0.1)',  value: '#a78bfa',  glow: 'rgba(167,139,250,0.07)'},
  default: { icon: '#94a3b8',  iconBg: 'rgba(148,163,184,0.08)', value: '#ffffff',  glow: 'transparent'          },
}

export function StatCard({ title, value, icon: Icon, accent = 'default', href, trend, subtitle }: StatCardProps) {
  const a = ACCENT[accent]
  const isPositiveTrend = (trend?.value ?? 0) >= 0

  const inner = (
    <div
      className={cn(
        'group relative flex items-center gap-4 p-5 rounded-[12px] transition-all duration-200',
        href && 'cursor-pointer hover:border-[rgba(255,255,255,0.10)] hover:translate-y-[-1px]',
      )}
      style={{
        background: 'linear-gradient(135deg, rgba(10,15,28,0.95) 0%, rgba(8,12,22,0.9) 100%)',
        border: '1px solid rgba(255,255,255,0.06)',
        boxShadow: `inset 0 1px 0 rgba(255,255,255,0.04), 0 1px 20px rgba(0,0,0,0.4)`,
      }}
    >
      {/* Subtle accent glow behind icon */}
      <div
        className="absolute top-0 left-0 w-16 h-16 rounded-[12px] pointer-events-none"
        style={{ background: `radial-gradient(circle at 30% 30%, ${a.glow}, transparent 70%)` }}
      />

      {/* Icon */}
      <div
        className="w-10 h-10 rounded-[10px] flex items-center justify-center flex-shrink-0"
        style={{ background: a.iconBg, border: `1px solid ${a.icon}22` }}
      >
        <Icon className="w-5 h-5" style={{ color: a.icon }} strokeWidth={1.75} />
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <p className="text-[11px] font-medium mb-1 truncate" style={{ color: 'rgba(255,255,255,0.38)' }}>
          {title}
        </p>
        <div className="flex items-baseline gap-2">
          <span className="text-[22px] font-black font-mono leading-none tracking-tight text-white">
            {value}
          </span>
          {trend && (
            <span
              className="flex items-center gap-0.5 text-[10px] font-bold"
              style={{ color: isPositiveTrend ? '#8BFF3E' : '#ef4444' }}
            >
              {isPositiveTrend ? (
                <TrendingUp className="w-3 h-3" />
              ) : (
                <TrendingDown className="w-3 h-3" />
              )}
              {isPositiveTrend ? '+' : ''}{trend.value}%
            </span>
          )}
        </div>
        {(subtitle || trend?.label) && (
          <p className="text-[10px] mt-0.5 truncate" style={{ color: 'rgba(255,255,255,0.24)' }}>
            {subtitle ?? trend?.label}
          </p>
        )}
      </div>

      {/* Arrow */}
      {href && (
        <ArrowRight
          className="w-3.5 h-3.5 opacity-0 group-hover:opacity-100 transition-opacity flex-shrink-0"
          style={{ color: 'rgba(255,255,255,0.35)' }}
        />
      )}
    </div>
  )

  return href ? <Link href={href}>{inner}</Link> : inner
}
