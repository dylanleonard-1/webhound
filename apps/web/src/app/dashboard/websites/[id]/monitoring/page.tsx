'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { ArrowLeft, Globe } from 'lucide-react'
import { api, type WebsiteResponse } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { ScheduleList } from '@/components/monitoring/schedule-list'
import { WadeHistoryTimeline } from '@/components/monitoring/wade-history-timeline'
import { BaselineList } from '@/components/monitoring/baseline-list'

export default function WebsiteMonitoringPage() {
  const { id } = useParams<{ id: string }>()
  const [website, setWebsite] = useState<WebsiteResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [notFound, setNotFound] = useState(false)

  useEffect(() => {
    api.websites
      .get(id)
      .then(setWebsite)
      .catch((err: { status?: number }) => {
        if (err?.status === 404) setNotFound(true)
      })
      .finally(() => setLoading(false))
  }, [id])

  if (loading) {
    return <div className="p-8"><LoadingState /></div>
  }

  if (notFound || !website) {
    return (
      <div className="max-w-4xl mx-auto p-6">
        <Link
          href="/dashboard/websites"
          className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors mb-6"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Websites
        </Link>
        <ErrorState message="Website not found or you don't have access to it." />
      </div>
    )
  }

  return (
    <div className="max-w-4xl mx-auto p-6 space-y-6">
      {/* Header */}
      <div>
        <Link
          href={`/dashboard/websites/${id}`}
          className="inline-flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-300 transition-colors mb-4"
        >
          <ArrowLeft className="w-3.5 h-3.5" />
          Back to Website
        </Link>
        <div className="flex items-center gap-2">
          <Globe className="w-4 h-4 text-gray-400" />
          <h1 className="text-lg font-semibold text-white">{website.hostname}</h1>
          <span className="text-xs text-gray-500">· Monitoring</span>
        </div>
      </div>

      {/* Schedules */}
      <ScheduleList websiteId={id} />

      {/* WADE history */}
      <WadeHistoryTimeline websiteId={id} />

      {/* Baselines */}
      <BaselineList websiteId={id} />
    </div>
  )
}
