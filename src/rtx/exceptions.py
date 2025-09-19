class RTXError(Exception):
    """Base exception for Real Tracker X."""


class ManifestNotFound(RTXError):
    """Raised when no supported manifests are discovered."""


class AdvisoryServiceError(RTXError):
    """Raised when advisory sources cannot be queried."""


class ReportRenderingError(RTXError):
    """Raised when we fail to render output formats."""
