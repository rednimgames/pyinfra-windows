"""
.. warning::
    This connector is in alpha and may change in future releases.

The ``@winssh`` connector runs commands on Windows hosts over SSH (OpenSSH
Server, bundled with Windows since Server 2019 / Windows 10). Commands are
executed with ``powershell.exe -EncodedCommand``, so the remote user's default
shell (``cmd.exe`` or PowerShell) does not matter and no shell quoting is
required. File transfers use SFTP.

Connection data (``ssh_user``, ``ssh_key``, ``ssh_port``, ...) is identical to
the default ``@ssh`` connector.

Privilege escalation arguments (``_sudo``, ``_su_user``, ...) are not
supported: Windows OpenSSH grants members of the Administrators group a full
elevated token, so there is nothing to escalate to.

Examples using ``@winssh``:

.. code:: python

    # Get the Date fact
    pyinfra @winssh/192.168.3.232 --user Administrator fact windows_server.Date

    # Create a directory
    pyinfra @winssh/192.168.3.232 --user Administrator windows_files.directory 'C:/temp'

    # Run a PowerShell command
    pyinfra @winssh/192.168.3.232 --user Administrator exec -- Get-ComputerInfo
"""

from __future__ import annotations

import base64
from collections.abc import Iterable, Iterator, Mapping, MutableMapping
from typing import TYPE_CHECKING, Any

from typing_extensions import Unpack, override

from pyinfra import logger
from pyinfra.api.command import StringCommand
from pyinfra.api.exceptions import InventoryError
from pyinfra.api.output import echo
from pyinfra.connectors.ssh import SSHConnector
from pyinfra.connectors.util import CommandOutput, read_output_buffers, write_stdin

if TYPE_CHECKING:
    from pyinfra.api.arguments import ConnectorArguments

PRIVILEGE_ARGUMENTS = (
    "_sudo",
    "_sudo_user",
    "_use_sudo_login",
    "_sudo_password",
    "_preserve_sudo_env",
    "_su_user",
    "_use_su_login",
    "_su_shell",
    "_preserve_su_env",
    "_su_password",
    "_doas",
    "_doas_user",
    "_dzdo",
    "_dzdo_user",
)


def _quote_powershell_literal(value: str) -> str:
    return "'{0}'".format(str(value).replace("'", "''"))


def make_powershell_command(
    command: "StringCommand | str",
    env: Mapping[str, str] | None = None,
    chdir: str | None = None,
) -> str:
    """
    Build the PowerShell script for a command, applying ``_env`` and ``_chdir``
    as a script preamble. Returns the plain-text script (see
    ``encode_powershell_command`` for the wire format).
    """

    lines = [
        "$ProgressPreference = 'SilentlyContinue'",
        "$ErrorActionPreference = 'Stop'",
    ]

    if chdir:
        lines.append("Set-Location -LiteralPath {0}".format(_quote_powershell_literal(chdir)))

    for key, value in (env or {}).items():
        lines.append("$env:{0} = {1}".format(key, _quote_powershell_literal(value)))

    raw = command.get_raw_value() if isinstance(command, StringCommand) else str(command)
    lines.append(raw)

    lines.append("if ($null -eq $LASTEXITCODE) { exit 0 } else { exit $LASTEXITCODE }")
    return "\n".join(lines)


def encode_powershell_command(script: str) -> str:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return "powershell.exe -NoProfile -NonInteractive -EncodedCommand {0}".format(encoded)


def _sftp_path(path: str) -> str:
    return str(path).replace("\\", "/")


def _pop_privilege_arguments(arguments: MutableMapping[str, Any]) -> None:
    requested = [key for key in PRIVILEGE_ARGUMENTS if arguments.pop(key, None)]
    if requested:
        raise NotImplementedError(
            "The @winssh connector does not support privilege escalation arguments"
            " ({0}): Windows OpenSSH grants administrators an elevated token".format(
                ", ".join(requested),
            ),
        )


class WindowsSSHConnector(SSHConnector):
    """
    Connect to Windows hosts over SSH, executing commands via PowerShell.
    """

    handles_execution = True

    @override
    @staticmethod
    def make_names_data(name: str | None = None) -> Iterator[tuple[str, dict[str, str], list[str]]]:
        if name is None:
            raise InventoryError("No hostname provided!")

        yield "@winssh/{0}".format(name), {"ssh_hostname": name}, []

    @override
    def run_shell_command(
        self,
        command: StringCommand,
        print_output: bool = False,
        print_input: bool = False,
        **arguments: Unpack["ConnectorArguments"],
    ) -> tuple[bool, CommandOutput]:
        _pop_privilege_arguments(arguments)

        _get_pty = arguments.pop("_get_pty", False)
        _timeout = arguments.pop("_timeout", None)
        _stdin = arguments.pop("_stdin", None)
        _success_exit_codes = arguments.pop("_success_exit_codes", None)
        _env = arguments.pop("_env", None)
        _chdir = arguments.pop("_chdir", None)
        _shell_executable = arguments.pop("_shell_executable", None)

        if _shell_executable and _shell_executable.casefold() in {"cmd", "cmd.exe"}:
            raise NotImplementedError(
                "The @winssh connector does not support cmd; use PowerShell commands instead",
            )

        script = make_powershell_command(command, env=_env, chdir=_chdir)

        logger.debug("Running command on %s: %s", self.host.name, script)

        if print_input:
            echo("{0}>>> {1}".format(self.host.print_prefix, script), err=True)

        assert self.client is not None
        stdin_buffer, stdout_buffer, stderr_buffer = self.client.exec_command(
            encode_powershell_command(script),
            get_pty=_get_pty,
        )

        if _stdin:
            write_stdin(_stdin, stdin_buffer)
        stdin_buffer.close()

        combined_output = read_output_buffers(
            stdout_buffer,
            stderr_buffer,
            timeout=_timeout,
            print_output=print_output,
            print_prefix=self.host.print_prefix,
        )

        exit_status = stdout_buffer.channel.recv_exit_status()
        logger.debug("Command exit status: %i", exit_status)

        if _success_exit_codes:
            status = exit_status in _success_exit_codes
        else:
            status = exit_status == 0

        return status, combined_output

    @override
    def put_file(
        self,
        filename_or_io,
        remote_filename,
        remote_temp_filename=None,
        print_output: bool = False,
        print_input: bool = False,
        **arguments: Unpack["ConnectorArguments"],
    ) -> bool:
        _pop_privilege_arguments(arguments)

        self._put_file(filename_or_io, _sftp_path(remote_filename))

        if print_output:
            echo(
                "{0}file uploaded: {1}".format(self.host.print_prefix, remote_filename),
                err=True,
            )

        return True

    @override
    def get_file(
        self,
        remote_filename,
        filename_or_io,
        remote_temp_filename=None,
        print_output: bool = False,
        print_input: bool = False,
        **arguments: Unpack["ConnectorArguments"],
    ) -> bool:
        _pop_privilege_arguments(arguments)

        self._get_file(_sftp_path(remote_filename), filename_or_io)

        if print_output:
            echo(
                "{0}file downloaded: {1}".format(self.host.print_prefix, remote_filename),
                err=True,
            )

        return True

    @override
    def check_can_rsync(self):
        raise NotImplementedError("The @winssh connector does not support rsync")

    @override
    def rsync(
        self,
        src: str,
        dest: str,
        flags: Iterable[str],
        print_output: bool = False,
        print_input: bool = False,
        **arguments: Unpack["ConnectorArguments"],
    ):
        raise NotImplementedError("The @winssh connector does not support rsync")
