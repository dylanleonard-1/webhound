'use client'

import { useEffect, useState } from 'react'
import { useParams } from 'next/navigation'
import Link from 'next/link'
import { motion } from 'framer-motion'
import {
  ArrowLeft, Globe, Calendar, Zap, AlertCircle, CheckCircle,
  BarChart3, Scale, ShieldAlert, Activity, Globe2, Settings2, Download,
} from 'lucide-react'
import { api, type ScanResultDetail } from '@/lib/api'
import { LoadingState } from '@/components/loading-state'
import { ErrorState } from '@/components/error-state'
import { RiskScoreCard } from '@/components/results/risk-score-card'
import { SeverityBreakdownCard } from '@/components/results/severity-breakdown-card'
import { PerformanceSummary } from '@/components/results/performance-summary'
import { WADESummary } from '@/components/results/wade-summary'
import { ExternalDomainsSection } from '@/components/results/external-domains-section'
import { ThreatIntelDomainsSection } from '@/components/results/threat-intel-domains-section'
import { ComplianceSummary } from '@/components/results/compliance-summary'
import { ScanInsights } from '@/components/results/scan-insights'
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

/**
 * SectionHeader — visual separator that introduces each topic block.
 * Keeps the results page readable when there are 6+ sections stacked.
 */
function SectionHeader({
  icon: Icon, title, subtitle, accent = 'rgba(255,255,255,0.5)',
}: {
  icon: React.FC<{ className?: string; style?: React.CSSProperties }>
  title: string
  subtitle?: string
  accent?: string
}) {
  return (
    <div className="flex items-center gap-3 mt-2 mb-1">
      <div
        className="w-7 h-7 rounded-[8px] flex items-center justify-center flex-shrink-0"
        style={{ background: 'rgba(255,255,255,0.04)', border: '1px solid rgba(255,255,255,0.08)' }}
      >
        <Icon className="w-3.5 h-3.5" style={{ color: accent }} />
      </div>
      <div className="min-w-0">
        <h2 className="text-[13px] font-semibold text-white tracking-tight">{title}</h2>
        {subtitle && (
          <p className="text-[11px]" style={{ color: 'rgba(255,255,255,0.4)' }}>{subtitle}</p>
        )}
      </div>
      <div className="flex-1 h-px" style={{ background: 'rgba(255,255,255,0.06)' }} />
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
      <div className="max-w-[1100px] mx-auto px-4 py-5 sm:px-6 sm:py-8 space-y-6">

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

        {/* ============================================================ */}
        {/* Section: Overview — risk / severity / performance            */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.1 }}
        >
          <SectionHeader
            icon={BarChart3}
            title="Overview"
            subtitle="Risk score, severity breakdown, and scan-run performance."
            accent="#8BFF3E"
          />
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
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
          </div>
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Compliance & Standards Coverage                     */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.12 }}
        >
          <SectionHeader
            icon={Scale}
            title="Compliance &amp; Standards"
            subtitle="How findings map to PCI DSS, ISO 27001, SOC 2, HIPAA, OWASP, NIST, and CWE."
            accent="#a78bfa"
          />
          <ComplianceSummary scanResultId={id} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Scan Insights — v4 JSON metadata panels             */}
        {/* (correlated chains, asset map, threat-intel coverage,        */}
        {/*  evidence quality, browser pass). Renders nothing on older   */}
        {/*  scans pre-dating these fields.                              */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4, delay: 0.05 }}
        >
          <ScanInsights scannerMetadata={result.scanner_metadata} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Threat Intelligence — suspicious external domains   */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.14 }}
        >
          <SectionHeader
            icon={ShieldAlert}
            title="Threat Intelligence"
            subtitle="External domains scored against local classifier and (when enabled) VirusTotal / URLhaus."
            accent="#f97316"
          />
          <ThreatIntelDomainsSection scanResultId={id} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Findings — the full sortable / filterable table     */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.16 }}
        >
          <SectionHeader
            icon={AlertCircle}
            title="Findings"
            subtitle="All security issues, grouped by type. Click any row to see what it means and how to fix it."
            accent="#ef4444"
          />
          <GroupedFindingsTable scanResultId={id} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Behavioral Analysis (WADE)                          */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.18 }}
        >
          <SectionHeader
            icon={Activity}
            title="Behavioral Analysis"
            subtitle="WADE baseline-vs-current comparison: what changed since last scan."
            accent="#4F9CF9"
          />
          <WADESummary metadata={result.scanner_metadata} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: External-Domain Inventory                            */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.2 }}
        >
          <SectionHeader
            icon={Globe2}
            title="Third-Party Inventory"
            subtitle="Every external domain the page touches, grouped by recognised vendor category."
            accent="#22d3ee"
          />
          <ExternalDomainsSection
            scriptDomains={(result.scanner_metadata?.external_script_domains as string[] | undefined) ?? []}
            linkDomains={(result.scanner_metadata?.external_domains as string[] | undefined) ?? []}
          />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Engine Diagnostics                                  */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.22 }}
        >
          <SectionHeader
            icon={Settings2}
            title="Engine Diagnostics"
            subtitle="Per-engine timings, outcomes, and skipped reasons."
            accent="rgba(255,255,255,0.5)"
          />
          <EngineDiagnosticsTable scanResultId={id} />
        </motion.div>

        {/* ============================================================ */}
        {/* Section: Reports                                              */}
        {/* ============================================================ */}
        <motion.div
          className="space-y-3"
          initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.35, delay: 0.24 }}
        >
          <SectionHeader
            icon={Download}
            title="Reports"
            subtitle="Download the scan as PDF, JSON, CSV, or SARIF."
            accent="#8BFF3E"
          />
          <ReportDownloads scanResultId={id} />
        </motion.div>
      </div>
    </div>
  )
}
