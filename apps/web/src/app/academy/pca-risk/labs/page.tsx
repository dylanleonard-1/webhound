import { SectionHeading, AcademyCard, Pill } from '@/components/academy/ui'
import { ProgressChecklist } from '@/components/academy/progress-checklist'
import { LABS } from '@/lib/academy/pca-risk'

export default function LabsPage() {
  return (
    <div className="space-y-6">
      <SectionHeading
        kicker="Hands-on"
        title="Practical Labs"
        sub="Do these on paper or in a spreadsheet. They mirror the actual day-to-day of an IT Risk associate — pulling populations, testing samples, and producing defensible evidence."
      />
      <AcademyCard>
        <h2 className="text-sm font-semibold text-white">Lab progress</h2>
        <p className="mt-1 text-xs text-slate-500">Saved locally in your browser.</p>
        <div className="mt-3">
          <ProgressChecklist items={LABS.map((l) => l.title)} storageKey="pca-academy:labs" />
        </div>
      </AcademyCard>

      <div className="space-y-4">
        {LABS.map((lab) => (
          <AcademyCard key={lab.id}>
            <h2 className="text-base font-semibold text-accent-green">{lab.title}</h2>
            <p className="mt-2 text-sm text-slate-300"><span className="text-slate-500">Scenario:</span> {lab.scenario}</p>
            <p className="mt-1 text-sm text-slate-300"><span className="text-slate-500">Goal:</span> {lab.goal}</p>
            <ol className="mt-3 space-y-1.5">
              {lab.steps.map((s, i) => (
                <li key={s} className="flex gap-2 text-sm text-slate-300">
                  <span className="shrink-0 font-mono text-xs text-accent-green">{i + 1}.</span>
                  <span>{s}</span>
                </li>
              ))}
            </ol>
            <div className="mt-3 flex flex-wrap items-center gap-2">
              <Pill tone="green">Deliverable</Pill>
              <span className="text-sm text-slate-300">{lab.deliverable}</span>
            </div>
            {lab.tip ? <p className="mt-2 text-xs italic text-slate-500">Tip: {lab.tip}</p> : null}
          </AcademyCard>
        ))}
      </div>
    </div>
  )
}
