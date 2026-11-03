"""Bounded errors contain fixed public reason codes, never raw input values."""


class EvidenceError(ValueError):
    """A rejected input, identified by a stable, non-sensitive code."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)
