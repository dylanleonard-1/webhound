# WebHound — scanner/webhound/engines/compromise/__init__.py

from .hidden_iframes import HiddenIframesEngine
from .injected_js import InjectedJsEngine
from .seo_spam import SeoSpamEngine
from .suspicious_redirects import SuspiciousRedirectsEngine

__all__ = [
    "InjectedJsEngine",
    "HiddenIframesEngine",
    "SeoSpamEngine",
    "SuspiciousRedirectsEngine",
]
