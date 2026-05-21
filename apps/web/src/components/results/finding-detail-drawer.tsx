'use client'

import { useEffect, useState } from 'react'
import { X, ExternalLink, Shield, Code2, MapPin, FileText, Layers } from 'lucide-react'
import { api, type GroupedFindingResponse, type GroupedFindingDetailResponse, type EvidenceItem } from '@/lib/api'
import { Badge } from '@/components/ui/badge'
import { cn } from '@/lib/utils'

const SEVERITY_STYLE: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  info: 'bg-gray-500/15 text-gray-400 border-gray-500/30',
}

const CATEGORY_LABEL: Record<string, string> = {
  security_header: 'Security Headers',
  headers:         'Headers',
  javascript:      'JavaScript',
  cookies:         'Cookies',
  tls_dns:         'TLS / DNS',
  tls:             'TLS',
  dns:             'DNS',
  forms:           'Forms',
  recon:           'Reconnaissance',
  compromise:      'Compromise',
  technology:      'Technology',
  cors:            'CORS',
  api:             'API',
  anomaly_detection: 'Anomaly',
  informational:   'Informational',
}

const FRAMEWORK_LABELS: Record<string, string> = {
  owasp_top10: 'OWASP',
  cwe_ids: 'CWE',
  nist_controls: 'NIST',
  sans_top25: 'SANS',
  pci_dss: 'PCI',
  gdpr: 'GDPR',
}

interface FindingDetailDrawerProps {
  finding: GroupedFindingResponse | null
  scanResultId: string
  onClose: () => void
}

function EvidenceCard({ item, index }: { item: EvidenceItem; index: number }) {
  return (
    <div className="bg-app-card rounded-lg p-3 space-y-1.5">
      <div className="flex items-center gap-2">
        <span className="text-[10px] font-mono text-gray-600 uppercase">
          #{index + 1} {item.type ?? 'finding'}
        </span>
      </div>
      {item.location && (
        <a
          href={item.location}
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center gap-1.5 text-xs font-mono text-accent-blue hover:text-accent-blue/80 transition-colors group"
        >
          <span className="flex-1 truncate">{item.location}</span>
          <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 flex-shrink-0" />
        </a>
      )}
      {item.content && (
        <p className="text-xs text-gray-400 leading-relaxed whitespace-pre-wrap break-words">
          {item.content}
        </p>
      )}
    </div>
  )
}

export function FindingDetailDrawer({ finding, scanResultId, onClose }: FindingDetailDrawerProps) {
  const [detail, setDetail] = useState<GroupedFindingDetailResponse | null>(null)
  const [loadingDetail, setLoadingDetail] = useState(false)

  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [onClose])

  useEffect(() => {
    if (!finding) {
      setDetail(null)
      return
    }
    setDetail(null)
    setLoadingDetail(true)
    api.scanResults
      .groupedFindingDetail(scanResultId, finding.id)
      .then(setDetail)
      .catch(() => { /* detail load failure is non-fatal; fall back to base finding data */ })
      .finally(() => setLoadingDetail(false))
  }, [finding, scanResultId])

  if (!finding) return null

  const active = detail ?? finding
  const description = detail?.description ?? finding.description
  const sampleEvidence = detail?.sample_evidence ?? []
  const frameworks = active.framework ?? {}
  const frameworkEntries = Object.entries(frameworks).filter(
    ([, v]) => Array.isArray(v) && v.length > 0,
  )

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black/50 backdrop-blur-[2px] z-40"
        onClick={onClose}
        aria-hidden="true"
      />

      {/* Drawer */}
      <aside className="fixed inset-y-0 right-0 w-full max-w-lg bg-[#0D1220] border-l border-app-border z-50 flex flex-col shadow-2xl">
        {/* Header */}
        <div className="flex items-start gap-3 p-5 border-b border-app-border">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1.5 flex-wrap">
              <Badge className={SEVERITY_STYLE[finding.severity] ?? SEVERITY_STYLE.info}>
                {finding.severity}
              </Badge>
              <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/20">
                {CATEGORY_LABEL[finding.category] ?? finding.category.replace(/_/g, ' ')}
              </Badge>
              <Badge className="bg-accent-blue/10 text-accent-blue border-accent-blue/20 font-mono text-[10px]">
                {finding.scanner_engine}
              </Badge>
            </div>
            <h2 className="text-base font-semibold text-white leading-snug">{finding.title}</h2>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded text-gray-500 hover:text-white hover:bg-white/5 transition-colors flex-shrink-0"
          >
            <X className="w-4 h-4" />
          </button>
        </div>

        {/* Scrollable body */}
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          {/* Stats row */}
          <div className="grid grid-cols-3 gap-3">
            <div className="bg-app-card rounded-lg p-3 text-center">
              <p className="text-xl font-mono font-bold text-white">{finding.affected_url_count}</p>
              <p className="text-[10px] text-gray-500 mt-0.5">Affected URLs</p>
            </div>
            <div className="bg-app-card rounded-lg p-3 text-center">
              <p className="text-xl font-mono font-bold text-white">{finding.evidence_count}</p>
              <p className="text-[10px] text-gray-500 mt-0.5">Evidence Items</p>
            </div>
            <div className="bg-app-card rounded-lg p-3 text-center">
              <p className={cn(
                'text-xl font-mono font-bold',
                finding.confidence !== null && finding.confidence >= 0.8
                  ? 'text-accent-green'
                  : finding.confidence !== null && finding.confidence >= 0.5
                    ? 'text-yellow-400'
                    : 'text-gray-400',
              )}>
                {finding.confidence !== null ? `${(finding.confidence * 100).toFixed(0)}%` : '—'}
              </p>
              <p className="text-[10px] text-gray-500 mt-0.5">Confidence</p>
            </div>
          </div>

          {/* Description */}
          {(description || loadingDetail) && (
            <section>
              <div className="flex items-center gap-2 mb-2">
                <FileText className="w-3.5 h-3.5 text-gray-400" />
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                  What This Means
                </h3>
              </div>
              {loadingDetail && !description ? (
                <div className="h-4 bg-gray-800 rounded animate-pulse" />
              ) : description ? (
                <p className="text-sm text-gray-300 leading-relaxed">{description}</p>
              ) : null}
            </section>
          )}

          {/* Remediation */}
          {finding.remediation && (
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Shield className="w-3.5 h-3.5 text-accent-green" />
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                  How to Fix
                </h3>
              </div>
              <p className="text-sm text-gray-300 leading-relaxed bg-accent-green/5 border border-accent-green/15 rounded-lg p-3">
                {finding.remediation}
              </p>
            </section>
          )}

          {/* Affected URLs */}
          {finding.affected_urls && finding.affected_urls.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-2">
                <MapPin className="w-3.5 h-3.5 text-gray-400" />
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Affected URLs ({finding.affected_url_count})
                </h3>
              </div>
              <div className="space-y-1">
                {finding.affected_urls.map((url, i) => (
                  <a
                    key={i}
                    href={url}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="flex items-center gap-2 text-xs font-mono text-accent-blue hover:text-accent-blue/80 bg-app-card rounded px-2 py-1.5 transition-colors group"
                  >
                    <span className="flex-1 truncate">{url}</span>
                    <ExternalLink className="w-3 h-3 opacity-0 group-hover:opacity-100 flex-shrink-0" />
                  </a>
                ))}
                {finding.affected_url_count > finding.affected_urls.length && (
                  <p className="text-xs text-gray-500 pl-2">
                    + {finding.affected_url_count - finding.affected_urls.length} more URLs
                  </p>
                )}
              </div>
            </section>
          )}

          {/* Evidence */}
          {sampleEvidence.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Layers className="w-3.5 h-3.5 text-gray-400" />
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Evidence Samples
                </h3>
              </div>
              <div className="space-y-2">
                {sampleEvidence.slice(0, 5).map((ev, i) => (
                  <EvidenceCard key={i} item={ev} index={i} />
                ))}
                {finding.evidence_count > sampleEvidence.length && (
                  <p className="text-xs text-gray-500 pl-1">
                    + {finding.evidence_count - sampleEvidence.length} more evidence items
                  </p>
                )}
              </div>
            </section>
          )}

          {/* Framework mappings */}
          {frameworkEntries.length > 0 && (
            <section>
              <div className="flex items-center gap-2 mb-2">
                <Code2 className="w-3.5 h-3.5 text-gray-400" />
                <h3 className="text-xs font-medium text-gray-300 uppercase tracking-wider">
                  Compliance Mappings
                </h3>
              </div>
              <div className="space-y-1.5">
                {frameworkEntries.map(([key, values]) => {
                  const label = FRAMEWORK_LABELS[key] ?? key.toUpperCase().replace(/_/g, ' ')
                  return (
                    <div key={key} className="flex items-start gap-3 bg-app-card rounded-lg px-3 py-2">
                      <span className="text-[10px] font-mono text-gray-500 w-12 flex-shrink-0 mt-0.5 uppercase">
                        {label}
                      </span>
                      <div className="flex flex-wrap gap-1">
                        {values.map((v, i) => (
                          <Badge
                            key={i}
                            className="bg-gray-500/10 text-gray-300 border-gray-500/20 text-[10px] font-mono"
                          >
                            {v}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )
                })}
              </div>
            </section>
          )}

          {/* Empty state when detail loaded but nothing extra to show */}
          {!loadingDetail && !description && sampleEvidence.length === 0 && frameworkEntries.length === 0 && !finding.remediation && !finding.affected_urls?.length && (
            <p className="text-xs text-gray-600 text-center py-4">
              No additional detail available for this finding.
            </p>
          )}
        </div>
      </aside>
    </>
  )
}
