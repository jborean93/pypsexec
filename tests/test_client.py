# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import io
import os
import pytest
import time

from smbclient import (
    listdir,
    open_file,
)

from pypsexec.client import (
    Client,
)

from pypsexec.exceptions import (
    PAExecException,
    PypsexecException,
)

from pypsexec.paexec import (
    ProcessPriority,
)

from pypsexec.scmr import (
    EnumServiceState,
    Service,
    ServiceType,
)


class TestClient(object):

    def test_client_loads(self):
        # a very basic test that ensure the file still loads
        client = Client("server", "username", "password")
        assert client.server == "server"
        assert client.port == 445
        assert isinstance(client.pid, int)
        assert isinstance(client.current_host, str)

    def test_port_override(self):
        client = Client("server", "username", "password", port=123)
        assert client.server == "server"
        assert client.port == 123
        assert isinstance(client.pid, int)
        assert isinstance(client.current_host, str)

    def test_proc_both_elevated_and_limited_error(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami", run_elevated=True, run_limited=True)
        assert str(exc.value) == "Both run_elevated and run_limited are set, only 1 of these can be true"

    def test_proc_stdin_and_async(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami", asynchronous=True, stdin=io.BytesIO(b""))
        assert str(exc.value) == "Cannot send stdin data on an interactive or asynchronous process"

    def test_proc_stdin_and_interactive(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami", interactive=True, stdin=io.BytesIO(b""))
        assert str(exc.value) == "Cannot send stdin data on an interactive or asynchronous process"


# these are the functional, they only run in the presence of env vars
class TestClientFunctional(object):

    @pytest.fixture(scope='class')
    def client(self):
        server = os.environ.get('PYPSEXEC_SERVER', None)
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)

        if server and username and password:
            with Client(server, username=username, password=password, encrypt=False) as client:
                yield client
        else:
            pytest.skip("PYPSEXEC_SERVER, PYPSEXEC_USERNAME, PYPSEXEC_PASSWORD environment variables were not set. "
                        "Integration tests will be skipped")

    def test_create_service_that_already_exists(self, client):
        actual = client.run_executable("whoami.exe")
        assert len(actual[0]) > 0
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_executable(self, client):
        actual = client.run_executable("whoami.exe")
        assert len(actual[0]) > 0
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_args(self, client):
        actual = client.run_executable("cmd.exe", arguments="/c echo hello world")
        assert actual[0] == b"hello world\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_long_running(self, client):
        arguments = "Write-Host first; Start-Sleep -Seconds 15; " \
                    "Write-Host second"
        actual = client.run_executable("powershell.exe", arguments=arguments)
        assert actual[0] == b"first\nsecond\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_stderr(self, client):
        arguments = "/c echo first && echo second 1>&2 && echo third"
        actual = client.run_executable("cmd.exe", arguments=arguments)
        assert actual[0] == b"first \r\nthird\r\n"
        assert actual[1] == b"second  \r\n"
        assert actual[2] == 0

    def test_proc_custom_stdout_stderr(self, client):
        stdout = io.BytesIO()
        stderr = io.BytesIO()

        arguments = "/c echo first && echo second 1>&2 && echo third"
        actual = client.run_executable("cmd.exe", arguments=arguments, stdout=stdout, stderr=stderr)
        assert actual[0] is None
        assert actual[1] is None
        assert stdout.getvalue() == b"first \r\nthird\r\n"
        assert stderr.getvalue() == b"second  \r\n"
        assert actual[2] == 0

    def test_proc_with_exit_code(self, client):
        actual = client.run_executable("cmd.exe", arguments="/c exit 10")
        assert actual[0] == b""
        assert actual[1] == b""
        assert actual[2] == 10

    def test_proc_limit_processor(self, client):
        actual = client.run_executable("powershell.exe", arguments="Write-Host hello", processors=[1])
        assert actual[0] == b"hello\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_dont_load_profile(self, client):
        actual = client.run_executable("powershell.exe", arguments="Write-Host done", load_profile=False)
        assert actual[0] == b"done\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_interactive(self, client):
        actual = client.run_executable("powershell.exe", arguments="Write-Host done", interactive=True)
        assert actual[0] is None
        assert actual[1] is None
        assert actual[2] == 0

    def test_proc_run_as_system(self, client):
        actual = client.run_executable("whoami.exe", use_system_account=True)
        assert actual[0] == b"nt authority\\system\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_run_specific_user(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe", arguments="/groups", username=username, password=password)
        # Can't test this in appveyor as admin approval mode is turned off
        # so the user is always an administrator
        # assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_run_invalid_user(self, client):
        with pytest.raises(PAExecException) as exc:
            client.run_executable("whoami.exe", username="fakeuser", password="fakepassword")
        assert str(exc.value) == "Received exception from remote PAExec service: Error logging in as fakeuser The " \
                                 "user name or password is incorrect. [Err=0x52E, 1326]\r\n"

    def test_proc_run_elevated(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe", arguments="/groups", username=username, password=password,
                                       run_elevated=True)
        assert b"High Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_run_limited(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe", arguments="/groups", username=username, password=password,
                                       run_limited=True)
        # Can't test this in appveyor as admin approval mode is turned off
        # so the user is always an administrator
        # assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_working_dir(self, client):
        actual = client.run_executable("cmd.exe", arguments="/c cd", working_dir="C:\\Windows")
        assert actual[0] == b"C:\\Windows\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_higher_priority(self, client):
        actual = client.run_executable("powershell.exe", arguments="Write-Host hi",
                                       priority=ProcessPriority.HIGH_PRIORITY_CLASS)
        assert actual[0] == b"hi\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_timeout(self, client):
        start_time = time.time()
        actual = client.run_executable("powershell.exe", arguments="Start-Sleep -Seconds 20", timeout_seconds=5)
        actual_time = time.time() - start_time
        # give it some leeway due to starting the service and sending the input
        assert int(actual_time) < 10
        assert actual[0] == b""
        assert actual[1] == b""
        assert actual[2] == 4294967286  # -10 PAExec error (timeout expired)

    def test_proc_with_stdin(self, client):
        actual = client.run_executable("powershell.exe", arguments="-", stdin=b"Write-Host input\r\nexit 0\r\n")
        assert actual[0] == b"input\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_stdin_as_io(self, client):
        stdin = io.BytesIO(b"Write-Host input1\r\nWrite-Host input2\r\nexit 0\r\n")
        actual = client.run_executable("powershell.exe", arguments="-", stdin=stdin)
        assert actual[0] == b"input1\ninput2\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_async(self, client):
        start_time = time.time()
        actual = client.run_executable("powershell.exe", arguments="Start-Sleep -Seconds 10", asynchronous=True)
        actual_time = time.time() - start_time
        assert int(actual_time) < 5
        assert actual[0] is None
        assert actual[1] is None
        # this is the pid of the async process so don't know in advance so just
        # make sure it isn't 0
        assert actual[2] != 0

    @pytest.mark.parametrize('wow, expected', [(None, 8), (False, 8), (True, 4)])
    def test_process_architecture(self, wow, expected, client):
        kwargs = {
            'arguments': '[System.IntPtr]::Size',
        }
        if wow is not None:
            kwargs['wow64'] = wow

        actual = client.run_executable('powershell.exe', **kwargs)

        assert int(actual[0].rstrip(b'\r\n')) == expected

    def test_cleanup_with_older_processes(self, client):
        client.remove_service()
        client.disconnect()
        client.connect()

        with open_file(r"\\%s\ADMIN$\PAExec-1234-hostname.exe" % client.server, mode='wb') as fd:
            fd.write(b"data")

        with open_file(r"\\%s\ADMIN$\PAExec-4567-other.exe" % client.server, mode='wb') as fd:
            fd.write(b"data")

        s1 = Service("PAExec-1234-hostname", client.server)
        s1.open()
        s1.create(r"C:\Windows\PAExec-1234-hostname")
        s1.close()

        s2 = Service("PAExec-8910-hostname", client.server)
        s2.open()
        s2.create(r"C:\Windows\PAExec-8910-hostname")
        s2.close()

        client.cleanup()

        scmr = client._service._scmr
        services = scmr.enum_services_status_w(
            client._service._scmr_handle,
            ServiceType.SERVICE_WIN32_OWN_PROCESS,
            EnumServiceState.SERVICE_STATE_ALL,
        )
        actual_services = [s['service_name'] for s in services if s['service_name'].lower().startswith('paexec')]
        actual_files = listdir(r"\\%s\ADMIN$" % client.server, "PAExec-*.exe")

        assert actual_services == []
        assert actual_files == []

        # Validate it doesn't fail on a 2nd run
        client.cleanup()
