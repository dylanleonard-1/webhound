import { notFound } from 'next/navigation'
import Link from 'next/link'
import { ArrowRight, Clock } from 'lucide-react'
import { SectionHeading, AcademyCard, Pill, QABlock } from '@/components/academy/ui'
import { MODULES, getModule, ACADEMY_BASE } from '@/lib/academy/pca-risk'

export function generateStaticParams() {
  return MODULES.map((m) => ({ slug: m.slug }))
}

export default async function ModulePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params
  const mod = getModule(slug)
  if (!mod) notFound()

  const idx = MODULES.findIndex((m) => m.slug === mod.slug)
  const next = MODULES[idx + 1]

  return (
    <div className="space-y-6">
      <SectionHeading kicker={`Phase ${mod.phase} · Module`} title={mod.title} sub={mod.tagline} />

      <div className="flex flex-wrap items-center gap-2">
        <Pill tone="green"><Clock className="mr-1 inline h-3 w-3" />~{mod.minutes} min</Pill>
        {mod.keyTerms.map((t) => <Pill key={t}>{t}</Pill>)}
      </div>

      {mod.sections.map((s) => (
        <AcademyCard key={s.heading}>
          <h2 className="text-base font-semibold text-accent-green">{s.heading}</h2>
          <div className="mt-2 space-y-2">
            {s.body.map((p, i) => (
              <p key={i} className="text-sm leading-relaxed text-slate-300">{p}</p>
            ))}
          </div>
          {s.bullets ? (
            <ul className="mt-3 space-y-1.5">
              {s.bullets.map((b) => (
                <li key={b} className="flex gap-2 text-sm text-slate-300">
                  <span className="mt-1.5 h-1 w-1 shrink-0 rounded-full bg-accent-green" />
                  <span>{b}</span>
                </li>
              ))}
            </ul>
          ) : null}
        </AcademyCard>
      ))}

      <div>
        <h2 className="mb-3 text-sm font-semibold text-white">Interview questions for this module</h2>
        <div className="space-y-2">
          {mod.interview.map((qa) => <QABlock key={qa.q} q={qa.q} a={qa.a} />)}
        </div>
      </div>

      <div className="flex items-center justify-between border-t border-app-border pt-4">
        <Link href={`${ACADEMY_BASE}/flashcards`} className="text-xs text-slate-400 hover:text-white">
          Drill flashcards →
        </Link>
        {next ? (
          <Link href={`${ACADEMY_BASE}/modules/${next.slug}`}
            className="inline-flex items-center gap-1 rounded-lg bg-accent-green/15 px-3 py-2 text-sm text-accent-green hover:bg-accent-green/25">
            Next: {next.title} <ArrowRight className="h-4 w-4" />
          </Link>
        ) : (
          <Link href={`${ACADEMY_BASE}/interview`}
            className="inline-flex items-center gap-1 rounded-lg bg-accent-green/15 px-3 py-2 text-sm text-accent-green hover:bg-accent-green/25">
            Interview mastery <ArrowRight className="h-4 w-4" />
          </Link>
        )}
      </div>
    </div>
  )
}
