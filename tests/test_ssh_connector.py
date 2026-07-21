import base64

from unittest import TestCase

import pytest
from pyinfra.api.command import StringCommand

from pyinfra_windows.connectors.ssh import (
    WindowsSSHConnector,
    _pop_privilege_arguments,
    encode_powershell_command,
    make_powershell_command,
)

from .util import make_inventory


def decode_encoded_command(command_line):
    prefix = "powershell.exe -NoProfile -NonInteractive -EncodedCommand "
    assert command_line.startswith(prefix)
    return base64.b64decode(command_line[len(prefix) :]).decode("utf-16-le")


class TestWindowsSSHConnector(TestCase):
    def test_connect_host(self):
        inventory = make_inventory(hosts=[("@winssh/somehost", {})])
        host = inventory.get_host("@winssh/somehost")
        assert host.data.ssh_hostname == "somehost"

    def test_make_powershell_command(self):
        script = make_powershell_command("Get-Date")
        assert "$ErrorActionPreference = 'Stop'" in script
        assert "Get-Date" in script
        assert script.endswith(
            "if ($null -eq $LASTEXITCODE) { exit 0 } else { exit $LASTEXITCODE }"
        )

    def test_make_powershell_command_env_and_chdir(self):
        script = make_powershell_command(
            "Get-ChildItem",
            env={"MY_VAR": "it's here"},
            chdir="C:\\temp",
        )
        assert "Set-Location -LiteralPath 'C:\\temp'" in script
        assert "$env:MY_VAR = 'it''s here'" in script
        assert script.index("Set-Location") < script.index("Get-ChildItem")

    def test_encode_powershell_command_roundtrip(self):
        script = make_powershell_command("Get-Date")
        assert decode_encoded_command(encode_powershell_command(script)) == script

    def test_privilege_arguments_rejected(self):
        with pytest.raises(NotImplementedError, match="_sudo"):
            _pop_privilege_arguments({"_sudo": True})

    def test_falsy_privilege_arguments_are_stripped(self):
        arguments = {"_sudo": False, "_su_user": None, "_timeout": 10}
        _pop_privilege_arguments(arguments)
        assert arguments == {"_timeout": 10}

    def test_cmd_shell_rejected(self):
        connector = object.__new__(WindowsSSHConnector)

        for shell_executable in ("cmd", "cmd.exe", "CMD.EXE"):
            with self.subTest(shell_executable=shell_executable):
                with pytest.raises(NotImplementedError, match="does not support cmd"):
                    connector.run_shell_command(
                        StringCommand("echo hello"),
                        _shell_executable=shell_executable,
                    )

    def test_rsync_rejected(self):
        connector = object.__new__(WindowsSSHConnector)

        with pytest.raises(NotImplementedError, match="does not support rsync"):
            connector.check_can_rsync()

        with pytest.raises(NotImplementedError, match="does not support rsync"):
            connector.rsync("source", "destination", ())
