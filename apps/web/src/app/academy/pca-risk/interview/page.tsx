import { SectionHeading, AcademyCard, QABlock } from '@/components/academy/ui'
import { INTERVIEW } from '@/lib/academy/pca-risk'

export default function InterviewPage() {
  return (
    <div className="space-y-6">
      <SectionHeading
        kicker="Phase 8 · Interview mastery"
        title="Interview Prep"
        sub="Model answers in your own voice — practical, honest, entry-to-mid level. They position WebHound and Log(N) Pacific as transferable control/evidence experience without overclaiming seniority. Read them, then say them out loud in your words."
      />
      {INTERVIEW.map((cat) => (
        <AcademyCard key={cat.id}>
          <h2 className="text-base font-semibold text-accent-green">{cat.title}</h2>
          <p className="mt-1 text-xs text-slate-500">{cat.blurb}</p>
          <div className="mt-3 space-y-2">
            {cat.questions.map((qa) => <QABlock key={qa.q} q={qa.q} a={qa.a} />)}
          </div>
        </AcademyCard>
      ))}
    </div>
  )
}
