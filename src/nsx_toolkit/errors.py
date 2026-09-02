"""Exception types shared across the toolkit."""


class NsxError(Exception):
    """Any failure talking to (or interpreting a response from) NSX."""


class UserAbort(Exception):
    """The operator backed out of a prompt ('b', Ctrl-C, or EOF)."""


class ConfigError(Exception):
    """Inventory, taxonomy, or credential configuration is unusable."""
