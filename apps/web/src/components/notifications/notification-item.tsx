'use client'

import Link from 'next/link'
import { Trash2, ExternalLink } from 'lucide-react'
import { type NotificationResponse, type NotificationSeverity } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

interface NotificationItemProps {
  notification: NotificationResponse
  onMarkRead: (id: string) => void
  onDelete: (id: string) => void
  isDeleting?: boolean
}

const SEV_BADGE: Record<NotificationSeverity, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const TYPE_LABEL: Record<string, string> = {
  scan_completed: 'Scan Completed',
  scan_failed: 'Scan Failed',
  high_risk_finding: 'High Risk',
  critical_finding: 'Critical Finding',
  wade_anomaly: 'WADE Anomaly',
  schedule_failed: 'Schedule Failed',
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1) return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}h ago`
  return `${Math.floor(h / 24)}d ago`
}

export function NotificationItem({ notification: n, onMarkRead, onDelete, isDeleting }: NotificationItemProps) {
  const resultHref = n.scan_result_id ? `/dashboard/results/${n.scan_result_id}` : null

  return (
    <div
      className={cn(
        'flex items-start gap-3 px-4 py-3 border-b border-app-border last:border-b-0 transition-colors',
        n.is_read ? 'opacity-60' : 'bg-white/[0.01]',
      )}
    >
      {/* Unread dot */}
      <div className="w-4 flex justify-center pt-1.5 flex-shrink-0">
        {!n.is_read && (
          <button
            onClick={() => onMarkRead(n.id)}
            title="Mark as read"
            className="w-2 h-2 rounded-full bg-accent-green hover:bg-accent-green/70 transition-colors flex-shrink-0"
          />
        )}
      </div>

      {/* Content */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap mb-0.5">
          <Badge className={cn('text-[10px]', SEV_BADGE[n.severity] ?? SEV_BADGE.info)}>
            {n.severity}
          </Badge>
          <span className="text-[11px] text-gray-500">{TYPE_LABEL[n.type] ?? n.type}</span>
        </div>
        <p className="text-sm text-gray-200 truncate">{n.title}</p>
        <p className="text-xs text-gray-500 mt-0.5 line-clamp-2">{n.message}</p>
        <p className="text-[11px] text-gray-600 mt-1">{timeAgo(n.created_at)}</p>
      </div>

      {/* Actions */}
      <div className="flex items-center gap-1 flex-shrink-0">
        {resultHref && (
          <Link
            href={resultHref}
            className="p-1.5 text-gray-500 hover:text-accent-blue transition-colors"
            title="View result"
          >
            <ExternalLink className="w-3.5 h-3.5" />
          </Link>
        )}
        <button
          onClick={() => onDelete(n.id)}
          disabled={isDeleting}
          className="p-1.5 text-gray-500 hover:text-red-400 transition-colors disabled:opacity-40"
          title="Delete"
        >
          <Trash2 className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}
