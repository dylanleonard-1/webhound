import Link from 'next/link'
import { ArrowRight } from 'lucide-react'
import { SectionHeading, AcademyCard, Pill } from '@/components/academy/ui'
import { ROADMAP, ACADEMY_BASE } from '@/lib/academy/pca-risk'

export default function RoadmapPage() {
  return (
    <div className="space-y-6">
      <SectionHeading
        kicker="Study plan"
        title="8-Phase Roadmap"
        sub="Work top to bottom. Phases 1–3 (Foundations, Audit, IAM) carry the most interview weight — front-load them."
      />
      <div className="space-y-4">
        {ROADMAP.map((p) => (
          <AcademyCard key={p.n}>
            <div className="flex items-start gap-4">
              <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-lg bg-accent-green/15 text-sm font-bold text-accent-green">
                P{p.n}
              </span>
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <h2 className="font-semibold text-white">{p.title}</h2>
                  {p.moduleSlug ? (
                    <Link href={`${ACADEMY_BASE}/modules/${p.moduleSlug}`}
                      className="inline-flex items-center gap-1 text-xs text-accent-green hover:underline">
                      Open module <ArrowRight className="h-3 w-3" />
                    </Link>
                  ) : (
                    <Link href={`${ACADEMY_BASE}/interview`}
                      className="inline-flex items-center gap-1 text-xs text-accent-green hover:underline">
                      Interview prep <ArrowRight className="h-3 w-3" />
                    </Link>
                  )}
                </div>
                <p className="mt-1 text-sm text-slate-400">{p.goal}</p>
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {p.topics.map((t) => <Pill key={t}>{t}</Pill>)}
                </div>
              </div>
            </div>
          </AcademyCard>
        ))}
      </div>
    </div>
  )
}
