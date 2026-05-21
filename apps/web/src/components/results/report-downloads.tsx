'use client'

import { useEffect, useState } from 'react'
import { Download, FileJson, FileText, FileCode, Table } from 'lucide-react'
import { api, type ReportResponse, type ReportFormat } from '@/lib/api'
import { Card } from '@/components/ui/card'
import { LoadingState } from '@/components/loading-state'

interface ReportDownloadsProps {
  scanResultId: string
}

const FORMAT_META: Record<ReportFormat, {
  label: string
  icon: React.FC<{ className?: string }>
  ext: string
  mime: string
  description: string
}> = {
  json:     { label: 'JSON',     icon: FileJson, ext: 'json',   mime: 'application/json',  description: 'Full machine-readable data' },
  sarif:    { label: 'SARIF',    icon: FileCode, ext: 'sarif',  mime: 'application/json',  description: 'For GitHub / VS Code' },
  csv:      { label: 'CSV',      icon: Table,    ext: 'csv',    mime: 'text/csv',           description: 'For spreadsheets' },
  markdown: { label: 'Markdown', icon: FileText, ext: 'md',     mime: 'text/markdown',      description: 'Human-readable report' },
}

function extractContent(report: ReportResponse): string {
  if (!report.content_json) return ''
  if (report.format === 'csv' || report.format === 'markdown') {
    if (typeof (report.content_json as { content?: unknown }).content === 'string') {
      return (report.content_json as { content: string }).content
    }
  }
  return JSON.stringify(report.content_json, null, 2)
}

function triggerDownload(content: string, filename: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

export function ReportDownloads({ scanResultId }: ReportDownloadsProps) {
  const [reports, setReports] = useState<ReportResponse[]>([])
  const [loading, setLoading] = useState(true)
  const [downloading, setDownloading] = useState<string | null>(null)

  useEffect(() => {
    api.scanResults.reports(scanResultId)
      .then(setReports)
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [scanResultId])

  async function handleDownload(report: ReportResponse) {
    setDownloading(report.id)
    try {
      const fresh = await api.scanResults.reportByFormat(scanResultId, report.format)
      const meta = FORMAT_META[fresh.format] ?? FORMAT_META.json
      const content = extractContent(fresh)
      if (!content) return
      triggerDownload(content, `webhound-${scanResultId.slice(0, 8)}.${meta.ext}`, meta.mime)
    } catch {
      // silently ignore — user sees the button re-enable
    } finally {
      setDownloading(null)
    }
  }

  if (loading) {
    return (
      <Card>
        <div className="flex items-center gap-2 p-4 border-b border-app-border">
          <Download className="w-4 h-4 text-gray-400" />
          <h2 className="font-medium text-white">Export Report</h2>
        </div>
        <div className="p-6"><LoadingState /></div>
      </Card>
    )
  }

  if (reports.length === 0) return null

  return (
    <Card>
      <div className="flex items-center justify-between p-4 border-b border-app-border">
        <div className="flex items-center gap-2">
          <Download className="w-4 h-4 text-gray-400" />
          <h2 className="font-medium text-white">Export Report</h2>
        </div>
        <span className="text-[11px] text-gray-500">Share results with your team or developer</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 p-4">
        {reports.map(report => {
          const meta = FORMAT_META[report.format] ?? FORMAT_META.json
          const Icon = meta.icon
          const isDownloading = downloading === report.id
          const unavailable = !report.content_json
          return (
            <button
              key={report.id}
              onClick={() => handleDownload(report)}
              disabled={isDownloading || unavailable}
              title={unavailable ? 'Report not yet generated' : `Download ${meta.label} report`}
              className="flex flex-col items-center gap-1.5 p-4 rounded-lg border border-app-border bg-app-card hover:border-accent-green/40 hover:bg-accent-green/5 transition-colors disabled:opacity-40 disabled:cursor-not-allowed group"
            >
              <Icon className="w-6 h-6 text-gray-400 group-hover:text-accent-green transition-colors" />
              <span className="text-xs font-medium text-gray-300">{meta.label}</span>
              <span className="text-[10px] text-gray-600">{meta.description}</span>
              {isDownloading && (
                <span className="text-[10px] text-accent-green animate-pulse">Downloading…</span>
              )}
            </button>
          )
        })}
      </div>
    </Card>
  )
}
