import { cn } from '@/lib/utils'
import { Card } from '@/components/ui/card'
import { Shield } from 'lucide-react'

interface RiskScoreCardProps {
  score: number
  level: string
}

const LEVEL_CONFIG: Record<string, {
  color: string
  ring: string
  label: string
  description: string
}> = {
  critical: {
    color: 'text-red-400',
    ring: 'border-red-500/40',
    label: 'Critical Risk',
    description: 'Urgent action required. Multiple serious vulnerabilities present — start with the Fix First section.',
  },
  high: {
    color: 'text-orange-400',
    ring: 'border-orange-500/40',
    label: 'High Risk',
    description: 'Significant issues found. These should be addressed soon to protect your visitors.',
  },
  medium: {
    color: 'text-yellow-400',
    ring: 'border-yellow-500/40',
    label: 'Medium Risk',
    description: 'Some security gaps found. Worth fixing to reduce your overall exposure.',
  },
  low: {
    color: 'text-accent-green',
    ring: 'border-accent-green/40',
    label: 'Low Risk',
    description: 'Minor issues only. Your site is reasonably secure — a few small improvements recommended.',
  },
  safe: {
    color: 'text-accent-green',
    ring: 'border-accent-green/40',
    label: 'Safe',
    description: 'No significant security issues found. Continue monitoring with regular scans.',
  },
  none: {
    color: 'text-accent-green',
    ring: 'border-accent-green/40',
    label: 'Safe',
    description: 'No significant security issues found. Continue monitoring with regular scans.',
  },
}

export function RiskScoreCard({ score, level }: RiskScoreCardProps) {
  const cfg = LEVEL_CONFIG[level] ?? LEVEL_CONFIG.low

  return (
    <Card className="p-5 flex flex-col items-center justify-center gap-3 text-center">
      <div className="flex items-center gap-2 text-xs font-medium text-gray-400 uppercase tracking-wider">
        <Shield className="w-3.5 h-3.5" />
        Risk Score
      </div>
      <div
        className={cn(
          'w-20 h-20 rounded-full border-4 flex flex-col items-center justify-center',
          cfg.ring,
        )}
      >
        <span className={cn('text-2xl font-bold font-mono leading-none', cfg.color)}>
          {score}
        </span>
        <span className="text-[9px] text-gray-500 mt-0.5 font-mono">/100</span>
      </div>
      <div>
        <span className={cn('text-sm font-medium block', cfg.color)}>{cfg.label}</span>
        <p className="text-[11px] text-gray-500 mt-1 max-w-[180px] leading-relaxed">
          {cfg.description}
        </p>
      </div>
    </Card>
  )
}
