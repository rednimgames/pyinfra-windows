"""
The windows module handles misc windows operations.
"""

import ntpath
import os

from pyinfra import host, state
from pyinfra.api import operation
from pyinfra.api.exceptions import OperationValueError

from pyinfra_windows.facts.server import AuthorizedKeys

ADMINISTRATORS_AUTHORIZED_KEYS = "C:\\ProgramData\\ssh\\administrators_authorized_keys"

# Tip: Use 'Get-Command -Noun Service' to search for what commands are available or
# simply 'Get-Command' to see what you can do...)

# Tip: To see the windows help page about a command, use 'Get-Help'.
# Might have to run 'Update-Help' if you want to use arguments like '-Examples'.
# ex: 'Get-Help Stop-Service'
# ex: 'Get-Help Stop-Service -Examples'
# ex: 'Get-Help Stop-Service -Detailed'
# ex: 'Get-Help Stop-Service -Full'

# FUTURE: add ability to stop processes (ex: "Stop-Process <id>")


@operation(is_idempotent=False)
def service(service, running=True, restart=False, suspend=False):
    """
    Stop/Start a Windows service.

    + service: name of the service to manage
    + running: whether the the service should be running or stopped
    + restart: whether the the service should be restarted
    + suspend: whether the the service should be suspended

    **Example:**

    .. code:: python

        windows.service(
            name="Stop the spooler service",
            service="service",
            running=False,
        )
    """

    if suspend or not running:
        if suspend:
            yield "Suspend-Service -Name {0}".format(service)
        else:
            yield "Stop-Service -Name {0}".format(service)
    else:
        if restart:
            yield "Restart-Service -Name {0}".format(service)
        else:
            if running:
                yield "Start-Service -Name {0}".format(service)


@operation(is_idempotent=False)
def reboot():
    """
    Restart the server.
    """
    yield "Restart-Computer -Force"


def _quote_powershell_literal(value: str) -> str:
    return "'{0}'".format(str(value).replace("'", "''"))


@operation()
def user_authorized_keys(
    public_keys: str | list[str],
    user: str | None = None,
    delete_keys: bool = False,
    authorized_key_directory: str | None = None,
    authorized_key_filename: str | None = None,
):
    """
    Manage SSH ``authorized_keys`` on Windows (OpenSSH Server).

    + public_keys: list of public keys to attach, either key strings or local key file paths
    + user: user whose keys to manage; defaults to the shared administrators file
    + delete_keys: whether to remove any keys not specified in ``public_keys``
    + authorized_key_directory: directory containing the authorized keys file
    + authorized_key_filename: filename of the authorized keys file

    Members of the ``Administrators`` group authenticate against the shared
    ``C:\\ProgramData\\ssh\\administrators_authorized_keys`` file, which is the
    target when no ``user`` or ``authorized_key_directory`` is given. Managing
    keys for a non-administrator user requires ``authorized_key_directory``.

    Public keys:
        These can be provided as strings containing the public key or as a path
        to a public key file which pyinfra will read.

    **Examples:**

    .. code:: python

        server.user_authorized_keys(
            name="Ensure administrator public keys",
            public_keys=["ssh-ed25519 AAAA..."],
            delete_keys=True,
        )
    """

    if isinstance(public_keys, str):
        public_keys = [public_keys]

    def read_any_pub_key_file(key: str) -> list[str]:
        try_path = key
        if state.cwd:
            try_path = os.path.join(state.cwd, key)

        if os.path.exists(try_path):
            with open(try_path) as f:
                return [line.strip() for line in f.readlines() if line.strip()]

        return [key.strip()]

    public_keys = [
        key for key_or_file in public_keys for key in read_any_pub_key_file(key_or_file)
    ]

    is_administrators_file = user is None and authorized_key_directory is None
    if is_administrators_file:
        authorized_key_file = ADMINISTRATORS_AUTHORIZED_KEYS
    else:
        if authorized_key_directory is None:
            raise OperationValueError(
                "Managing per-user authorized_keys requires authorized_key_directory"
            )
        authorized_key_file = ntpath.join(
            authorized_key_directory,
            authorized_key_filename or "authorized_keys",
        )

    current_keys = host.get_fact(AuthorizedKeys, path=authorized_key_file)

    if delete_keys:
        desired_keys = list(dict.fromkeys(public_keys))
    else:
        desired_keys = list(current_keys)
        desired_keys.extend(
            key for key in dict.fromkeys(public_keys) if key not in current_keys
        )

    if desired_keys == current_keys:
        host.noop("authorized keys are up to date")
        return

    key_literals = ", ".join(_quote_powershell_literal(key) for key in desired_keys)
    yield "Set-Content -LiteralPath {0} -Value @({1}) -Encoding ascii".format(
        _quote_powershell_literal(authorized_key_file),
        key_literals,
    )

    if is_administrators_file:
        yield (
            "& icacls.exe {0} /inheritance:r /grant '*S-1-5-18:F' /grant '*S-1-5-32-544:F'"
        ).format(_quote_powershell_literal(authorized_key_file))
