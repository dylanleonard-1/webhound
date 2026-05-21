import { Card } from '@/components/ui/card'

interface SeverityBreakdownCardProps {
  breakdown: Record<string, number>
  actionable: number
  total: number
}

const LEVELS = [
  { key: 'critical', label: 'Critical', bar: 'bg-red-500', text: 'text-red-400' },
  { key: 'high', label: 'High', bar: 'bg-orange-500', text: 'text-orange-400' },
  { key: 'medium', label: 'Medium', bar: 'bg-yellow-500', text: 'text-yellow-400' },
  { key: 'low', label: 'Low', bar: 'bg-blue-500', text: 'text-blue-400' },
  { key: 'info', label: 'Info', bar: 'bg-gray-500', text: 'text-gray-400' },
]

export function SeverityBreakdownCard({ breakdown, actionable, total }: SeverityBreakdownCardProps) {
  const max = Math.max(1, ...LEVELS.map(l => breakdown[l.key] ?? 0))

  return (
    <Card className="p-5 space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-xs font-medium text-gray-400 uppercase tracking-wider">
          Severity Breakdown
        </p>
        <span className="text-xs text-gray-500 font-mono">
          {actionable} actionable / {total} total
        </span>
      </div>

      <div className="space-y-2.5">
        {LEVELS.map(({ key, label, bar, text }) => {
          const count = breakdown[key] ?? 0
          const pct = (count / max) * 100
          return (
            <div key={key} className="flex items-center gap-3">
              <span className="w-14 text-xs text-right text-gray-500 flex-shrink-0">{label}</span>
              <div className="flex-1 h-1.5 rounded-full bg-white/5 overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${bar}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
              <span className={`w-6 text-xs font-mono font-medium text-right ${text}`}>
                {count}
              </span>
            </div>
          )
        })}
      </div>
    </Card>
  )
}
