import { SectionHeading } from '@/components/academy/ui'
import { FlashcardDeck } from '@/components/academy/flashcard-deck'
import { FLASHCARDS } from '@/lib/academy/pca-risk'

export default function FlashcardsPage() {
  return (
    <div>
      <SectionHeading
        kicker="Active recall"
        title="Flashcards"
        sub="Pick a module, flip each card, and try to answer before flipping. Cycle until you can answer every card cold."
      />
      <FlashcardDeck groups={FLASHCARDS} />
    </div>
  )
}
