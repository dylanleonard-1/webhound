'use client'

// /admin is an alias of the internal command center. Redirect to /control,
// which enforces the RBAC gate.
import { useEffect } from 'react'
import { useRouter } from 'next/navigation'

export default function AdminRedirect() {
  const router = useRouter()
  useEffect(() => { router.replace('/control') }, [router])
  return null
}
