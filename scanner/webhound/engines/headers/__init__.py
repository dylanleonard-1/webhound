# WebHound — scanner/webhound/engines/headers/__init__.py

from .cors import CorsEngine
from .security_headers import SecurityHeadersEngine

__all__ = ["SecurityHeadersEngine", "CorsEngine"]
