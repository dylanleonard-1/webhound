'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import { ArrowLeft, Globe, Calendar, Zap, AlertCircle, CheckCircle, Info } from 'lucide-react'
import { api, type ScanResultDetail } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { RiskScoreCard } from '@/components/results/risk-score-card'
import { SeverityBreakdownCard } from '@/components/results/severity-breakdown-card'
import { PerformanceSummary } from '@/components/results/performance-summary'
import { WADESummary } from '@/components/results/wade-summary'
import { ExternalDomainsSection } from '@/components/results/external-domains-section'
import { GroupedFindingsTable } from '@/components/results/grouped-findings-table'
import { EngineDiagnosticsTable } from '@/components/results/engine-diagnostics-table'
import { ReportDownloads } from '@/components/results/report-downloads'

const PROFILE_COLOR: Record<string, string> = {
  quick:    '#22d3ee',
  standard: '#8BFF3E',
  deep:     '#a78bfa',
  monitor:  '#f97316',
}

function formatDate(iso: string) {
  return new Date(iso).toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit',
  })
}

function ScanSummaryBanner({ result }: { result: ScanResultDetail }) {
  const actionable = result.actionable_findings
  const critical = (result.severity_breakdown?.critical ?? 0) as number
  const high = (result.severity_breakdown?.high ?? 0) as number

  if (actionable === 0) {
    return (
      <div
        className="flex items-start gap-3 rounded-[10px] px-4 py-3"
        style={{ background: 'rgba(139,255,62,0.05)', border: '1px solid rgba(139,255,62,0.18)' }}
      >
        <CheckCircle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: '#8BFF3E' }} />
        <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.7)' }}>
          <span className="font-semibold" style={{ color: '#8BFF3E' }}>No actionable findings. </span>
          WebHound scanned {result.pages_crawled} {result.pages_crawled === 1 ? 'page' : 'pages'} and found no
          security issues that need immediate attention.
        </p>
      </div>
    )
  }

  const urgentCount = critical + high
  return (
    <div
      className="flex items-start gap-3 rounded-[10px] px-4 py-3"
      style={{ background: 'rgba(249,115,22,0.05)', border: '1px solid rgba(249,115,22,0.2)' }}
    >
      <AlertCircle className="w-4 h-4 flex-shrink-0 mt-0.5" style={{ color: '#f97316' }} />
      <p className="text-[13px]" style={{ color: 'rgba(255,255,255,0.7)' }}>
        {urgentCount > 0 && (
          <>
            <span className="font-semibold" style={{ color: '#f97316' }}>
              {urgentCount} urgent {urgentCount === 1 ? 'issue' : 'issues'}
            </span>
            {' '}({critical > 0 ? `${critical} critical` : ''}{critical > 0 && high > 0 ? ', ' : ''}{high > 0 ? `${high} high` : ''}) — start with the{' '}
            <span className="font-semibold text-white">Fix First</span> section below.{' '}
          </>
        )}
        {actionable} {actionable === 1 ? 'issue' : 'issues'} found across {result.pages_crawled} {result.pages_crawled === 1 ? 'page' : 'pages'}.
        Click any finding to see what it means and how to fix it.
      </p>
    </div>
  )
}

export default function ScanResultPage() {
  const { id } = useParams<{ id: string }>()
  const [result, setResult] = useState<ScanResultDetail | null>(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')

  useEffect(() => {
    api.scanResults.get(id)
      .then(setResult)
      .catch(() => setError('Failed to load scan result.'))
      .finally(() => setLoading(false))
  }, [id])

  if (loading) return <div className="p-8"><LoadingState /></div>

  if (error || !result) {
    return <div className="p-8"><ErrorState message={error || 'Scan result not found.'} /></div>
  }

  const scanProfile = (result.scan_job?.profile ?? result.scanner_metadata?.scan_profile ?? 'standard') as string
  const profileColor = PROFILE_COLOR[scanProfile] ?? '#8BFF3E'

  return (
    <div className="flex-1 overflow-y-auto" style={{ scrollbarWidth: 'thin' }}>
      <div className="max-w-[1100px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-5">

        {/* Back + header */}
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35 }}>
          <Link
            href={`/dashboard/scans/${result.scan_job_id}`}
            className="inline-flex items-center gap-1.5 text-[12px] mb-4 transition-colors"
            style={{ color: 'rgba(255,255,255,0.35)' }}
            onMouseEnter={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.65)')}
            onMouseLeave={e => (e.currentTarget.style.color = 'rgba(255,255,255,0.35)')}
          >
            <ArrowLeft className="w-3.5 h-3.5" />
            Back to Scan Job
          </Link>

          <div className="flex flex-col sm:flex-row sm:items-start sm:justify-between gap-3">
            <div>
              <div className="flex items-center gap-2 mb-1">
                <Globe className="w-4 h-4" style={{ color: 'rgba(255,255,255,0.35)' }} />
                <h1 className="text-[18px] font-bold text-white font-mono">
                  {result.website?.scheme}://{result.website?.hostname}
                </h1>
              </div>
              <div className="flex flex-wrap items-center gap-3 text-[11px]" style={{ color: 'rgba(255,255,255,0.35)' }}>
                <span className="flex items-center gap-1">
                  <Calendar className="w-3 h-3" />
                  {formatDate(result.created_at)}
                </span>
                <span
                  className="flex items-center gap-1 px-2 py-0.5 rounded-full text-[9px] font-bold uppercase"
                  style={{ background: `${profileColor}18`, color: profileColor, border: `1px solid ${profileColor}35` }}
                >
                  <Zap className="w-2.5 h-2.5" />
                  {scanProfile}
                </span>
              </div>
            </div>
          </div>
        </motion.div>

        {/* Summary banner */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.05 }}>
          <ScanSummaryBanner result={result} />
        </motion.div>

        {/* Top stat row */}
        <motion.div
          className="grid grid-cols-1 md:grid-cols-3 gap-4"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
        >
          <RiskScoreCard score={result.risk_score} level={result.risk_level} />
          <SeverityBreakdownCard
            breakdown={result.severity_breakdown}
            actionable={result.actionable_findings}
            total={result.total_findings}
          />
          <PerformanceSummary
            pagesCrawled={result.pages_crawled}
            durationSeconds={result.duration_seconds}
            totalFindings={result.total_findings}
            scanProfile={scanProfile}
            externalScriptDomainCount={result.scanner_metadata?.external_script_domain_count as number | undefined}
          />
        </motion.div>

        {/* Findings */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.15 }}>
          <GroupedFindingsTable scanResultId={id} />
        </motion.div>

        {/* Behavioral analysis */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.2 }}>
          <WADESummary metadata={result.scanner_metadata} />
        </motion.div>

        {/* External domains */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.22 }}>
          <ExternalDomainsSection
            scriptDomains={(result.scanner_metadata?.external_script_domains as string[] | undefined) ?? []}
            linkDomains={(result.scanner_metadata?.external_domains as string[] | undefined) ?? []}
          />
        </motion.div>

        {/* Engine diagnostics */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.24 }}>
          <EngineDiagnosticsTable scanResultId={id} />
        </motion.div>

        {/* Report downloads */}
        <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.26 }}>
          <ReportDownloads scanResultId={id} />
        </motion.div>
      </div>
    </div>
  )
}
