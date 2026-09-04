"""Exception types shared across the toolkit."""


class NsxError(Exception):
    """Any failure talking to (or interpreting a response from) NSX."""


class NsxHttpError(NsxError):
    """An NSX response with a status code worth acting on.

    A subclass rather than a new type so every existing `except NsxError`
    keeps catching it. The status matters in exactly one place today:
    NSX answers 412 when a write carries a stale `_revision`, which is
    "somebody else changed this object since you read it" -- a different
    outcome from a request that was merely malformed.
    """

    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


class UserAbort(Exception):
    """The operator backed out of a prompt ('b', Ctrl-C, or EOF)."""


class ConfigError(Exception):
    """Inventory, taxonomy, or credential configuration is unusable."""
