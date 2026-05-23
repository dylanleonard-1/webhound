import { redirect } from 'next/navigation'

// /features was a list of repackaged hero claims with no new info.
// Its content now lives on /scanner.
export default function FeaturesPage() {
  redirect('/scanner')
}
