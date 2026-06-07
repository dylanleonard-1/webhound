# WebHound — scanner/webhound/industry/__init__.py
# Phase-19 Industry-Specific Intelligence.
#
# Adapts WebHound's context, risk framing, recommendations, reporting, and
# WADE monitoring to the kind of small business being scanned — restaurants,
# dental practices, law firms, online stores, contractors, nonprofits, and
# professional services — instead of speaking generic-enterprise.
#
# Public API (import from here):
#
#     from webhound.industry import (
#         Industry, classify_industry, IndustrySignals,
#         classify_page, assess_vendor_on_page, assess_change,
#         recommendations_for, select_template, profile_for,
#     )
#
# Design guardrails: no compliance promises (no HIPAA/PCI claims), business-
# friendly language, technical detail preserved in the advanced view.

from __future__ import annotations

from webhound.industry.context_rules import (
    PageClassification,
    business_label_for,
    classify_page,
    scripts_touching_sensitive_flows,
    sensitive_pages_for,
    sensitive_pages_in_graph,
    vendors_connected_to_payment,
)
from webhound.industry.industry_classifier import (
    IndustryClassifier,
    classify_industry,
)
from webhound.industry.industry_profiles import PROFILES, profile_for
from webhound.industry.models import (
    SENSITIVE_PAGE_KINDS,
    BusinessLabel,
    Confidence,
    Industry,
    IndustryClassification,
    IndustryProfile,
    IndustrySignals,
    PageKind,
    ReviewPriority,
    industry_from_value,
)
from webhound.industry.recommendation_rules import (
    IndustryRecommendation,
    baseline_recommendations,
    recommendation_priorities,
    recommendations_for,
)
from webhound.industry.report_templates import (
    IndustryReportTemplate,
    ReportSection,
    report_sections_for,
    select_template,
)
from webhound.industry.risk_adjustments import (
    IndustryAssessment,
    assess_change,
    assess_vendor_on_page,
)
from webhound.industry.vendor_catalog import (
    IndustryVendor,
    is_known_industry_vendor,
    lookup,
    vendors_for,
)

__all__ = [
    # models
    "Industry", "Confidence", "PageKind", "BusinessLabel", "ReviewPriority",
    "IndustrySignals", "IndustryClassification", "IndustryProfile",
    "SENSITIVE_PAGE_KINDS", "industry_from_value",
    # classifier
    "IndustryClassifier", "classify_industry",
    # profiles
    "PROFILES", "profile_for",
    # context / pages / graph
    "PageClassification", "classify_page", "sensitive_pages_for",
    "business_label_for", "sensitive_pages_in_graph",
    "scripts_touching_sensitive_flows", "vendors_connected_to_payment",
    # vendor catalog
    "IndustryVendor", "lookup", "is_known_industry_vendor", "vendors_for",
    # risk adjustments / WADE
    "IndustryAssessment", "assess_vendor_on_page", "assess_change",
    # recommendations
    "IndustryRecommendation", "recommendations_for",
    "baseline_recommendations", "recommendation_priorities",
    # report templates
    "IndustryReportTemplate", "ReportSection", "report_sections_for",
    "select_template",
]
