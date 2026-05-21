// Mirrors the TRUSTED_DOMAINS set and _DOMAIN_CATEGORY dict in
// scanner/webhound/engines/javascript/third_party_domains.py.
// Used by ExternalDomainsSection to classify observed script sources in the UI.
// Keep in sync with the Python dicts when adding/removing domains.

export type DomainCategory =
  | 'CDN' | 'Analytics' | 'Tracking' | 'Payments' | 'Marketing'
  | 'Monitoring' | 'Support' | 'Social' | 'Video' | 'Security'
  | 'CMS' | 'Maps' | 'Community' | 'Unknown'

export const DOMAIN_CATEGORY: Readonly<Record<string, DomainCategory>> = {
  // CDN
  'googleapis.com': 'CDN', 'gstatic.com': 'CDN', 'googleusercontent.com': 'CDN',
  'cloudflare.com': 'CDN', 'cloudflare.net': 'CDN',
  'cloudfront.net': 'CDN', 'fastly.net': 'CDN', 'fastly.com': 'CDN',
  'akamaized.net': 'CDN', 'akamai.com': 'CDN', 'akamaihd.net': 'CDN',
  'jsdelivr.net': 'CDN', 'unpkg.com': 'CDN', 'bootstrapcdn.com': 'CDN',
  'jquery.com': 'CDN', 'jquery.org': 'CDN', 'amazonaws.com': 'CDN',
  'typekit.net': 'CDN', 'adobe.com': 'CDN', 'fonts.com': 'CDN',
  'github.io': 'CDN', 'github.com': 'CDN', 'githubusercontent.com': 'CDN',
  // Analytics
  'google-analytics.com': 'Analytics', 'googletagmanager.com': 'Analytics',
  'googleadservices.com': 'Analytics', 'googlesyndication.com': 'Analytics',
  'doubleclick.net': 'Analytics', 'hotjar.com': 'Analytics',
  'mixpanel.com': 'Analytics', 'amplitude.com': 'Analytics',
  'heap.io': 'Analytics', 'fullstory.com': 'Analytics', 'logrocket.com': 'Analytics',
  'segment.io': 'Analytics', 'segment.com': 'Analytics',
  // Tracking / Advertising
  'facebook.net': 'Tracking', 'facebook.com': 'Tracking', 'fbcdn.net': 'Tracking',
  'twitter.com': 'Tracking', 'twimg.com': 'Tracking',
  'pinterest.com': 'Tracking', 'tiktok.com': 'Tracking', 'addthis.com': 'Tracking',
  // Payments
  'stripe.com': 'Payments', 'stripe.network': 'Payments',
  'paypal.com': 'Payments', 'paypalobjects.com': 'Payments',
  'braintreegateway.com': 'Payments', 'square.com': 'Payments', 'squareup.com': 'Payments',
  // Marketing
  'mailchimp.com': 'Marketing', 'chimpstatic.com': 'Marketing',
  'hubspot.com': 'Marketing', 'hs-scripts.com': 'Marketing', 'hsforms.com': 'Marketing',
  'klaviyo.com': 'Marketing', 'constantcontact.com': 'Marketing', 'sendgrid.com': 'Marketing',
  // Monitoring
  'sentry.io': 'Monitoring', 'newrelic.com': 'Monitoring', 'nr-data.net': 'Monitoring',
  'datadog-browser-agent.com': 'Monitoring',
  // Support
  'intercomcdn.com': 'Support', 'intercom.io': 'Support',
  'zendesk.com': 'Support', 'zopim.com': 'Support',
  'freshworks.com': 'Support', 'tawk.to': 'Support',
  // Social
  'instagram.com': 'Social', 'linkedin.com': 'Social', 'licdn.com': 'Social',
  'gitlab.com': 'Social', 'bitbucket.org': 'Social',
  // Video
  'youtube.com': 'Video', 'ytimg.com': 'Video',
  'vimeo.com': 'Video', 'vimeocdn.com': 'Video',
  'wistia.com': 'Video', 'wistia.net': 'Video',
  'brightcove.net': 'Video', 'brightcove.com': 'Video',
  // Security / Auth
  'recaptcha.net': 'Security', 'hcaptcha.com': 'Security', 'captcha.net': 'Security',
  // CMS / Builders
  'shopify.com': 'CMS', 'myshopify.com': 'CMS', 'shopifycdn.com': 'CMS',
  'bigcommerce.com': 'CMS', 'ecwid.com': 'CMS',
  'squarespace.com': 'CMS', 'squarespace-cdn.com': 'CMS', 'sqspcdn.com': 'CMS',
  'wix.com': 'CMS', 'wixstatic.com': 'CMS', 'webflow.com': 'CMS', 'webflow.io': 'CMS',
  'wordpress.com': 'CMS', 'wp.com': 'CMS',
  // Maps
  'mapbox.com': 'Maps', 'openstreetmap.org': 'Maps',
  // Community
  'disqus.com': 'Community', 'disquscdn.com': 'Community',
}

export function getDomainCategory(host: string): DomainCategory {
  const parts = host.split('.')
  for (let i = 0; i < parts.length - 1; i++) {
    const candidate = parts.slice(i).join('.')
    const cat = DOMAIN_CATEGORY[candidate]
    if (cat) return cat
  }
  return 'Unknown'
}

export const TRUSTED_SCRIPT_DOMAINS: ReadonlySet<string> = new Set([
  // Google
  'googleapis.com', 'gstatic.com', 'googletagmanager.com',
  'google-analytics.com', 'google.com', 'googleadservices.com',
  'googlesyndication.com', 'googleusercontent.com',
  // CDNs
  'cloudflare.com', 'cloudflare.net',
  'jsdelivr.net', 'unpkg.com',
  'bootstrapcdn.com',
  'jquery.com', 'jquery.org',
  'cloudfront.net',
  'fastly.net', 'fastly.com',
  'akamaized.net', 'akamai.com', 'akamaihd.net',
  'amazonaws.com',
  // Social
  'facebook.net', 'facebook.com', 'fbcdn.net',
  'twitter.com', 'twimg.com',
  'linkedin.com', 'licdn.com',
  'instagram.com', 'pinterest.com', 'tiktok.com',
  // Dev
  'github.io', 'github.com', 'githubusercontent.com',
  'gitlab.com', 'bitbucket.org',
  // Analytics
  'hotjar.com', 'segment.io', 'segment.com', 'mixpanel.com',
  'amplitude.com', 'heap.io', 'fullstory.com', 'logrocket.com',
  'newrelic.com', 'nr-data.net', 'datadog-browser-agent.com', 'sentry.io',
  // Support / chat
  'intercomcdn.com', 'intercom.io', 'zendesk.com', 'zopim.com',
  'freshworks.com', 'tawk.to',
  // Payments
  'stripe.com', 'stripe.network', 'paypal.com', 'paypalobjects.com',
  'braintreegateway.com', 'square.com', 'squareup.com',
  // E-commerce
  'shopify.com', 'myshopify.com', 'shopifycdn.com', 'bigcommerce.com', 'ecwid.com',
  // Website builders
  'squarespace.com', 'squarespace-cdn.com', 'sqspcdn.com',
  'wix.com', 'wixstatic.com', 'webflow.com', 'webflow.io',
  'wordpress.com', 'wp.com',
  // Email marketing
  'mailchimp.com', 'chimpstatic.com', 'hubspot.com', 'hs-scripts.com',
  'hsforms.com', 'klaviyo.com', 'constantcontact.com', 'sendgrid.com',
  // Fonts
  'typekit.net', 'adobe.com', 'fonts.com',
  // Media / video
  'vimeo.com', 'vimeocdn.com', 'youtube.com', 'ytimg.com',
  'wistia.com', 'wistia.net', 'brightcove.net', 'brightcove.com',
  // Maps
  'mapbox.com', 'openstreetmap.org',
  // Misc
  'addthis.com', 'disqus.com', 'disquscdn.com',
  'captcha.net', 'recaptcha.net', 'hcaptcha.com',
])
