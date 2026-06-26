import { SectionHeading } from '@/components/academy/ui'
import { GlossarySearch } from '@/components/academy/glossary-search'
import { GLOSSARY } from '@/lib/academy/pca-risk'

export default function GlossaryPage() {
  return (
    <div>
      <SectionHeading
        kicker="Reference"
        title="Glossary"
        sub="Every term the interview can throw at you — search or filter by category. Note: SOC = System and Organization Controls, not Security Operations Center."
      />
      <GlossarySearch terms={GLOSSARY} />
    </div>
  )
}
