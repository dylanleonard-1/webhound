'use client'

import { useState, type FormEvent } from 'react'
import Link from 'next/link'
import { useRouter } from 'next/navigation'
import { ArrowLeft, Globe } from 'lucide-react'
import { api } from '@/lib/api'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

export default function NewWebsitePage() {
  const router = useRouter()
  const [url, setUrl] = useState('')
  const [displayName, setDisplayName] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [fieldErrors, setFieldErrors] = useState<string[]>([])

  async function handleSubmit(e: FormEvent) {
    e.preventDefault()
    if (!url.trim()) return
    setSubmitting(true)
    setError(null)
    setFieldErrors([])
    try {
      const site = await api.websites.create(
        url.trim(),
        displayName.trim() || undefined,
      )
      router.push(`/dashboard/websites/${site.id}`)
    } catch (err: unknown) {
      if (err && typeof err === 'object' && 'data' in err) {
        const apiErr = err as { status?: number; data?: { error?: { message?: string; details?: { errors?: Array<{ msg: string }> } } } }
        const errors = apiErr.data?.error?.details?.errors
        if (errors?.length) {
          setFieldErrors(errors.map(e => e.msg))
          setSubmitting(false)
          return
        }
        const apiMsg = apiErr.data?.error?.message
        if (apiMsg) {
          setError(apiMsg)
          setSubmitting(false)
          return
        }
      }
      const raw = err instanceof Error ? err.message : 'Failed to add website.'
      const msg = raw === 'Failed to fetch'
        ? 'Cannot reach the API server. Make sure the backend is running on port 8000.'
        : raw
      setError(msg)
      setSubmitting(false)
    }
  }

  return (
    <div className="p-4 sm:p-6 max-w-xl space-y-6">
      <div className="flex items-center gap-3">
        <Button variant="ghost" size="sm" asChild>
          <Link href="/dashboard/websites">
            <ArrowLeft className="w-4 h-4 mr-1" />
            Websites
          </Link>
        </Button>
      </div>

      <div>
        <h1 className="text-2xl font-semibold text-white">Add Website</h1>
        <p className="text-sm text-gray-400 mt-1">
          Start monitoring a website for security vulnerabilities.
        </p>
      </div>

      <Card className="p-5">
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <Label htmlFor="url">Website URL *</Label>
            <div className="relative">
              <Globe className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500 pointer-events-none" />
              <Input
                id="url"
                type="text"
                placeholder="https://example.com"
                value={url}
                onChange={e => setUrl(e.target.value)}
                className="pl-9 font-mono"
                required
                autoFocus
              />
            </div>
            <p className="mt-1.5 text-xs text-gray-500">
              Must use http:// or https://. Private/local addresses are not allowed.
            </p>
          </div>

          <div>
            <Label htmlFor="display-name">Display Name <span className="text-gray-500 font-normal">(optional)</span></Label>
            <Input
              id="display-name"
              type="text"
              placeholder="My Website"
              value={displayName}
              onChange={e => setDisplayName(e.target.value)}
              maxLength={100}
            />
          </div>

          {fieldErrors.length > 0 && (
            <ul className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2 space-y-1">
              {fieldErrors.map((msg, i) => (
                <li key={i}>• {msg}</li>
              ))}
            </ul>
          )}

          {error && (
            <p className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <div className="flex gap-3 pt-1">
            <Button type="submit" disabled={submitting || !url.trim()}>
              {submitting ? 'Adding…' : 'Add Website'}
            </Button>
            <Button type="button" variant="ghost" asChild>
              <Link href="/dashboard/websites">Cancel</Link>
            </Button>
          </div>
        </form>
      </Card>
    </div>
  )
}
