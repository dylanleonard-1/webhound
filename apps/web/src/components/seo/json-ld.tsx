// Renders a JSON-LD <script> for structured data. Server-safe (no client
// hooks) so it can be used in both server and client components. The script
// is inert and renders into the SSR HTML where crawlers read it.
export function JsonLd({ data }: { data: Record<string, unknown> }) {
  return (
    <script
      type="application/ld+json"
      // JSON.stringify output is safe to inline; no user input flows in here.
      dangerouslySetInnerHTML={{ __html: JSON.stringify(data) }}
    />
  )
}
