"""Exception types. The CLI turns any Cve2atError into a clean one-line message."""


class Cve2atError(Exception):
    """Base class for all expected, user-facing errors."""


class ConfigError(Cve2atError):
    """Bad CLI input (e.g. malformed CPE name) or missing environment pieces."""


class FetchError(Cve2atError):
    """The NVD API could not be queried successfully."""


class DatasetError(Cve2atError):
    """A reference dataset (CWE / CAPEC / ATT&CK) is missing or has the wrong columns."""


class PipelineError(Cve2atError):
    """A pipeline stage cannot continue (e.g. nothing left after filtering)."""
