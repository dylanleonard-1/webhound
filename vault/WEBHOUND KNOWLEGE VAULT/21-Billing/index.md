---
title: Billing
phase: 8G
---
<!-- WEBHOUND-GENERATED -->

# 21 — Billing

## Stack

| Component | Technology |
|-----------|-----------|
| Payment processor | Stripe |
| Router | `apps/api/routers/billing.py` |
| Service | `apps/api/services/customers.py` |
| Model | `apps/api/models/subscription.py` |

## Subscription Model

```python
class Subscription:
    id: UUID
    org_id: UUID
    stripe_sub_id: str
    tier: SubscriptionTier  # free | pro | enterprise
    status: str
    period_end: datetime
```

## Tiers (inferred from `billing/plans.py`)

| Tier | Features |
|------|---------|
| Free | Limited scans, basic findings |
| Pro | Full scanning, all modules, reports |
| Enterprise | SSO, multi-domain, advanced WADE, API |

## Provider Access

Subscription tier gates:
- Number of domains
- Scan frequency
- Provider integrations (Cloudflare, Vercel)
- Report exports
- Portfolio features

## See Also

- [[04-Backend/index|Backend]] · [[10-Providers/index|Providers]]
- [[05-Database/Database Entity Map|Entity Map (Subscription)]]

#webhound #billing #index
