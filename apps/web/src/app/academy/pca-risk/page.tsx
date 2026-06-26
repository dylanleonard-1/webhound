import Link from 'next/link'
import { ArrowRight, BookOpen, Brain, FlaskConical, ListChecks, Map, MessageSquare } from 'lucide-react'
import { AcademyCard, SectionHeading, Pill } from '@/components/academy/ui'
import { ProgressChecklist } from '@/components/academy/progress-checklist'
import {
  ACADEMY_BASE, MODULES, ROADMAP, GLOSSARY, INTERVIEW, FLASHCARDS, LABS,
  HIGH_YIELD_TERMS, STUDY_CHECKLIST,
} from '@/lib/academy/pca-risk'

const TILES = [
  { href: `${ACADEMY_BASE}/roadmap`, icon: Map, label: 'Roadmap', desc: '8-phase study plan' },
  { href: `${ACADEMY_BASE}/modules/${MODULES[0].slug}`, icon: BookOpen, label: 'Modules', desc: `${MODULES.length} full topics` },
  { href: `${ACADEMY_BASE}/glossary`, icon: Brain, label: 'Glossary', desc: `${GLOSSARY.length} terms` },
  { href: `${ACADEMY_BASE}/interview`, icon: MessageSquare, label: 'Interview Prep', desc: `${INTERVIEW.length} categories` },
  { href: `${ACADEMY_BASE}/flashcards`, icon: ListChecks, label: 'Flashcards', desc: `${FLASHCARDS.reduce((n, g) => n + g.cards.length, 0)} cards` },
  { href: `${ACADEMY_BASE}/labs`, icon: FlaskConical, label: 'Labs', desc: `${LABS.length} exercises` },
]

export default function AcademyDashboard() {
  return (
    <div className="space-y-8">
      <SectionHeading
        kicker="ITS Risk Management Associate"
        title="PCA Interview Study Academy"
        sub="A private, focused prep space for the IT Risk / SOX associate interview. Learn the controls, the audit mechanics, and how to talk about them honestly — then drill until it’s second nature."
      />

      {/* What this role really is */}
      <AcademyCard>
        <h2 className="text-sm font-semibold text-accent-green">What this role really is</h2>
        <p className="mt-2 text-sm leading-relaxed text-slate-300">
          You’re not “doing IT.” You’re testing that the IT controls behind a public company’s
          financial statements actually work — access, change, and operations controls — and proving it
          with evidence. It’s control thinking + evidence rigor + systematic testing. That’s the job, and
          it’s exactly the muscle you already use building a security scanner.
        </p>
        <div className="mt-3 flex flex-wrap gap-2">
          <Pill tone="green">SOX / ICFR</Pill>
          <Pill tone="blue">IT General Controls</Pill>
          <Pill>Audit evidence</Pill>
          <Pill>Entry-to-mid level</Pill>
        </div>
      </AcademyCard>

      {/* Priority order + countdown */}
      <div className="grid gap-4 md:grid-cols-3">
        <AcademyCard className="md:col-span-2">
          <h2 className="text-sm font-semibold text-white">Priority study order</h2>
          <ol className="mt-3 space-y-2">
            {ROADMAP.slice(0, 5).map((p) => (
              <li key={p.n} className="flex items-start gap-3 text-sm">
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-accent-green/15 text-[11px] font-bold text-accent-green">
                  {p.n}
                </span>
                <span className="text-slate-300">{p.title}</span>
              </li>
            ))}
          </ol>
          <Link href={`${ACADEMY_BASE}/roadmap`} className="mt-4 inline-flex items-center gap-1 text-xs text-accent-green hover:underline">
            See full 8-phase roadmap <ArrowRight className="h-3 w-3" />
          </Link>
        </AcademyCard>

        <AcademyCard>
          <h2 className="text-sm font-semibold text-white">Interview countdown</h2>
          <p className="mt-2 text-3xl font-bold text-accent-green">Set date</p>
          <p className="mt-1 text-xs text-slate-500">
            Placeholder — drop your interview date here and pace the roadmap backwards from it
            (Foundations → Audit → IAM first).
          </p>
        </AcademyCard>
      </div>

      {/* Module tiles */}
      <div>
        <h2 className="mb-3 text-sm font-semibold text-white">Jump into a module</h2>
        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {TILES.map((t) => (
            <Link key={t.href} href={t.href}
              className="group rounded-xl border border-app-border bg-app-card p-4 transition-colors hover:border-accent-green/40">
              <t.icon className="h-5 w-5 text-accent-green" />
              <p className="mt-2 text-sm font-semibold text-white">{t.label}</p>
              <p className="text-xs text-slate-500">{t.desc}</p>
            </Link>
          ))}
        </div>
      </div>

      {/* High-yield terms + checklist */}
      <div className="grid gap-4 md:grid-cols-2">
        <AcademyCard>
          <h2 className="text-sm font-semibold text-white">High-yield terms</h2>
          <p className="mt-1 text-xs text-slate-500">If you only memorize a dozen, memorize these.</p>
          <div className="mt-3 flex flex-wrap gap-1.5">
            {HIGH_YIELD_TERMS.map((t) => (
              <Link key={t} href={`${ACADEMY_BASE}/glossary`}>
                <Pill tone="blue">{t}</Pill>
              </Link>
            ))}
          </div>
        </AcademyCard>

        <AcademyCard>
          <h2 className="text-sm font-semibold text-white">Today’s study checklist</h2>
          <p className="mt-1 text-xs text-slate-500">Saved locally in your browser.</p>
          <div className="mt-3">
            <ProgressChecklist items={STUDY_CHECKLIST} storageKey="pca-academy:today" />
          </div>
        </AcademyCard>
      </div>
    </div>
  )
}
