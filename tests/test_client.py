import os
import sys
import time

import pytest

from pypsexec.client import Client
from pypsexec.exceptions import PAExecException, PypsexecException
from pypsexec.paexec import ProcessPriority

if sys.version[0] == '2':
    from Queue import Queue
else:
    from queue import Queue


class TestClient(object):

    def test_client_loads(self):
        # a very basic test that ensure the file still loads
        client = Client("username", "password", "server")
        assert client.server == "server"
        assert client.port == 445
        assert client.username == "username"
        assert client.password == "password"
        assert isinstance(client.pid, int)
        assert isinstance(client.current_host, str)

    def test_port_override(self):
        client = Client("username", "password", "server", port=123)
        assert client.server == "server"
        assert client.port == 123
        assert client.username == "username"
        assert client.password == "password"
        assert isinstance(client.pid, int)
        assert isinstance(client.current_host, str)

    def test_encode_string(self):
        client = Client("username", "password", "server")
        expected = "string".encode('utf-16-le')
        actual = client._encode_string("string")
        assert actual == expected

    def test_empty_blank_queue(self):
        client = Client("username", "password", "server")
        queue = Queue()
        expected = b""
        actual = client._empty_queue(queue)
        assert actual == expected

    def test_empty_filled_queue(self):
        client = Client("username", "password", "server")
        queue = Queue()
        queue.put(b"Hello")
        queue.put(b"\n")
        queue.put(b"World")
        expected = b"Hello\nWorld"
        actual = client._empty_queue(queue)
        assert actual == expected

    def test_proc_both_elevated_and_limited_error(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami",
                                  run_elevated=True,
                                  run_limited=True)
        assert str(exc.value) == "Both run_elevated and run_limited are " \
                                 "set, only 1 of these can be true"


# these are the functional, they only run in the presence of env vars
class TestClientFunctional(object):

    @pytest.fixture(scope='class')
    def client(self):
        server = os.environ.get('PYPSEXEC_SERVER', None)
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)

        if server and username and password:
            client = Client(username, password, server)
            client.connect()
            try:
                client.create_service()
                yield client
            finally:
                client.remove_service()
                client.disconnect()
        else:
            pytest.skip("PYPSEXEC_SERVER, PYPSEXEC_USERNAME, PYPSEXEC_PASSWORD"
                        " environment variables were not set. Integration "
                        "tests will be skipped")

    def test_create_srvice_that_already_exists(self, client):
        # ensure this can be run multiple times
        client.create_service()
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
        actual = client.run_executable("cmd.exe",
                                       arguments="/c echo hello world")
        assert actual[0] == b"hello world\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    @pytest.mark.skip("Need to find out but it sometimes freezes when the "
                      "proc is done")
    def test_proc_long_running(self, client):
        arguments = "Write-Host first; Start-Sleep -Seconds 30; " \
                    "Write-Host second"
        actual = client.run_executable("powershell.exe",
                                       arguments=arguments)
        assert actual[0] == b"first\nsecond\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_stderr(self, client):
        arguments = "/c echo first && echo second 1>&2 && echo third"
        actual = client.run_executable("cmd.exe",
                                       arguments=arguments)
        assert actual[0] == b"first \r\nthird\r\n"
        assert actual[1] == b"second  \r\n"
        assert actual[2] == 0

    def test_proc_with_exit_code(self, client):
        actual = client.run_executable("cmd.exe",
                                       arguments="/c exit 10")
        assert actual[0] == b""
        assert actual[1] == b""
        assert actual[2] == 10

    def test_proc_limit_processor(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host hello",
                                       processors=[1])
        assert actual[0] == b"hello\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_dont_load_profile(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host done",
                                       load_profile=False)
        assert actual[0] == b"done\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_interactive(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host done",
                                       interactive=True)
        assert actual[0] is None
        assert actual[1] is None
        assert actual[2] == 0

    def test_proc_run_as_system(self, client):
        actual = client.run_executable("whoami.exe",
                                       use_system_account=True)
        assert actual[0] == b"nt authority\\system\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_run_specific_user(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password)
        assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_run_invalid_user(self, client):
        with pytest.raises(PAExecException) as exc:
            client.run_executable("whoami.exe",
                                  username="fakeuser",
                                  password="fakepassword")
        assert str(exc.value) == "Received exception from remote PAExec " \
                                 "service: Error logging in as fakeuser The " \
                                 "user name or password is incorrect. " \
                                 "[Err=0x52E, 1326]\r\n"

    def test_proc_run_elevated(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password,
                                       run_elevated=True)
        assert b"High Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_run_limited(self, client):
        username = os.environ['PYPSEXEC_USERNAME']
        password = os.environ['PYPSEXEC_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password,
                                       run_limited=True)
        assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_working_dir(self, client):
        actual = client.run_executable("cmd.exe",
                                       arguments="/c cd",
                                       working_dir="C:\\Windows")
        assert actual[0] == b"C:\\Windows\r\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_higher_priority(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host hi",
                                       priority=ProcessPriority.
                                       HIGH_PRIORITY_CLASS)
        assert actual[0] == b"hi\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_timeout(self, client):
        start_time = time.time()
        actual = client.run_executable("powershell.exe",
                                       arguments="Start-Sleep -Seconds 20",
                                       timeout_seconds=5)
        actual_time = time.time() - start_time
        # give it some leeway due to starting the service and sending the input
        assert int(actual_time) < 10
        assert actual[0] == b""
        assert actual[1] == b""
        assert actual[2] == 4294967286  # -10 PAExec error (timeout expired)

    def test_proc_with_stdin(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="-",
                                       stdin=b"Write-Host input\r\nexit 0\r\n")
        assert actual[0] == b"input\n"
        assert actual[1] == b""
        assert actual[2] == 0

    def test_proc_with_asyn(self, client):
        start_time = time.time()
        actual = client.run_executable("powershell.exe",
                                       arguments="Start-Sleep -Seconds 20",
                                       async=True)
        actual_time = time.time() - start_time
        assert int(actual_time) < 5
        assert actual[0] is None
        assert actual[1] is None
        # this is the pid of the async process so don't know in advance so just
        # make sure it isn't 0
        assert actual[2] != 0
