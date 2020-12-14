# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import pytest
import sys
import time

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

from pypsexec.pipe import (
    OutputPipe,
)

from pypsexec.scmr import (
    EnumServiceState,
    Service,
    ServiceType,
)

from smbprotocol.connection import (
    NtStatus,
)

from smbprotocol.exceptions import (
    SMBResponseException,
)

from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    DirectoryAccessMask,
    FileAttributes,
    FileInformationClass,
    ImpersonationLevel,
    Open,
    ShareAccess,
)

from smbprotocol.tree import (
    TreeConnect,
)

if sys.version[0] == '2':
    from Queue import Queue
else:
    from queue import Queue


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

    def test_encode_string(self):
        client = Client("server", "username", "password")
        expected = "string".encode('utf-16-le')
        actual = client._encode_string("string")
        assert actual == expected

    def test_empty_blank_queue(self):
        client = Client("server", "username", "password")
        queue = Queue()
        expected = b""
        actual = client._empty_queue(queue)
        assert actual == expected

    def test_empty_filled_queue(self):
        client = Client("server", "username", "password")
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

    def test_proc_stdin_and_async(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami",
                                  asynchronous=True,
                                  stdin=b"")
        assert str(exc.value) == "Cannot send stdin data on an interactive " \
                                 "or asynchronous process"

    def test_proc_stdin_and_interactive(self):
        client = Client("username", "password", "server")
        with pytest.raises(PypsexecException) as exc:
            client.run_executable("whoami",
                                  interactive=True,
                                  stdin=b"")
        assert str(exc.value) == "Cannot send stdin data on an interactive " \
                                 "or asynchronous process"


# these are the functional, they only run in the presence of env vars
class TestClientFunctional(object):

    @pytest.fixture(scope='class')
    def client(self):
        server = os.environ.get('PYPSEXEC_SERVER', None)
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)

        if server:
            client = Client(server, username=username, password=password)
            client.connect()
            try:
                client.create_service()
                yield client
            finally:
                client.disconnect()
        else:
            pytest.skip("PYPSEXEC_SERVER, PYPSEXEC_USERNAME, PYPSEXEC_PASSWORD"
                        " environment variables were not set. Integration "
                        "tests will be skipped")

    def test_create_service_that_already_exists(self, client):
        actual = client.run_executable("whoami.exe")
        assert len(actual[0]) > 0
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_executable(self, client):
        actual = client.run_executable("whoami.exe")
        assert len(actual[0]) > 0
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_args(self, client):
        actual = client.run_executable("cmd.exe",
                                       arguments="/c echo hello world")
        assert actual[0] == b"hello world\r\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_long_running(self, client):
        arguments = "Write-Host first; Start-Sleep -Seconds 15; " \
                    "Write-Host second"
        actual = client.run_executable("powershell.exe",
                                       arguments=arguments)
        assert actual[0] == b"first\nsecond\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_stderr(self, client):
        arguments = "/c echo first && echo second 1>&2 && echo third"
        actual = client.run_executable("cmd.exe",
                                       arguments=arguments)
        assert actual[0] == b"first \r\nthird\r\n"
        assert actual[1] == b"second  \r\n"
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_custom_stdout_stderr(self, client):
        class OutputPipeList(OutputPipe):

            def __init__(self, tree, name):
                self.pipe_buffer = []
                super(OutputPipeList, self).__init__(tree, name)

            def handle_output(self, output):
                self.pipe_buffer.append(output)

            def get_output(self):
                return self.pipe_buffer

        arguments = "/c echo first && echo second 1>&2 && echo third"
        actual = client.run_executable("cmd.exe",
                                       arguments=arguments,
                                       stdout=OutputPipeList,
                                       stderr=OutputPipeList)
        assert actual[0] == [b"first \r\n", b"third\r\n"]
        assert actual[1] == [b"second  \r\n"]
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_exit_code(self, client):
        actual = client.run_executable("cmd.exe",
                                       arguments="/c exit 10")
        assert actual[0] == b""
        assert actual[1] == b""
        assert actual[2] == 10
        time.sleep(1)

    def test_proc_limit_processor(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host hello",
                                       processors=[1])
        assert actual[0] == b"hello\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_dont_load_profile(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host done",
                                       load_profile=False)
        assert actual[0] == b"done\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_interactive(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host done",
                                       interactive=True)
        assert actual[0] is None
        assert actual[1] is None
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_run_as_system(self, client):
        actual = client.run_executable("whoami.exe",
                                       use_system_account=True)
        assert actual[0] == b"nt authority\\system\r\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_run_specific_user(self, client):
        username = os.environ['PYPSEXEC_ALT_USERNAME']
        password = os.environ['PYPSEXEC_ALT_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password)
        # TODO: This requires admin approval mode to be on (UAC), be more flexible in the future.
        assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

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
        username = os.environ['PYPSEXEC_ALT_USERNAME']
        password = os.environ['PYPSEXEC_ALT_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password,
                                       run_elevated=True)
        assert b"High Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_run_limited(self, client):
        username = os.environ['PYPSEXEC_ALT_USERNAME']
        password = os.environ['PYPSEXEC_ALT_PASSWORD']
        actual = client.run_executable("whoami.exe",
                                       arguments="/groups",
                                       username=username,
                                       password=password,
                                       run_limited=True)
        # TODO: This requires admin approval mode to be on (UAC), be more flexible in the future.
        assert b"Medium Mandatory Level" in actual[0]
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_working_dir(self, client):
        actual = client.run_executable("cmd.exe",
                                       arguments="/c cd",
                                       working_dir="C:\\Windows")
        assert actual[0] == b"C:\\Windows\r\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_higher_priority(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="Write-Host hi",
                                       priority=ProcessPriority.
                                       HIGH_PRIORITY_CLASS)
        assert actual[0] == b"hi\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

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
        time.sleep(1)

    def test_proc_with_stdin(self, client):
        actual = client.run_executable("powershell.exe",
                                       arguments="-",
                                       stdin=b"Write-Host input\r\nexit 0\r\n")
        assert actual[0] == b"input\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_stdin_generator(self, client):
        def stdin_generator():
            yield b"Write-Host input1\r\n"
            yield b"Write-Host input2\r\n"
            yield b"exit 0\r\n"

        actual = client.run_executable("powershell.exe",
                                       arguments="-",
                                       stdin=stdin_generator)
        assert actual[0] == b"input1\ninput2\n"
        assert actual[1] == b""
        assert actual[2] == 0
        time.sleep(1)

    def test_proc_with_async(self, client):
        start_time = time.time()
        actual = client.run_executable("powershell.exe",
                                       arguments="Start-Sleep -Seconds 10",
                                       asynchronous=True)
        actual_time = time.time() - start_time
        assert int(actual_time) < 5
        assert actual[0] is None
        assert actual[1] is None
        # this is the pid of the async process so don't know in advance so just
        # make sure it isn't 0
        assert actual[2] != 0
        time.sleep(1)

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
        # create a new service with different pid and service name
        new_client = self._get_new_generic_client(client)
        new_client.connect()
        new_client.create_service()

        # ensure a single call to remove_service deletes the service and files
        new_client.remove_service()
        new_client.disconnect()

        client, services, files = self._get_paexec_files_and_services(client)
        assert len(services) >= 1
        assert len(files) >= 1

        # now create a client but don't cleanup afterwards
        new_client = self._get_new_generic_client(client)
        new_client.connect()
        new_client.create_service()
        new_client.disconnect()

        client, services, files = self._get_paexec_files_and_services(client)
        assert len(services) >= 2
        assert len(files) >= 2

        client.cleanup()

        client, services, files = self._get_paexec_files_and_services(client)
        assert len(services) == 0
        assert len(files) == 0

        # make sure it works on multiple runs
        client.cleanup()

        client, services, files = self._get_paexec_files_and_services(client)
        assert len(services) == 0
        assert len(files) == 0

    def _get_paexec_files_and_services(self, client):
        server = os.environ['PYPSEXEC_SERVER']
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)
        paexec_services = []

        # need to close and reopen the connection to ensure deletes are
        # processed
        client.disconnect()
        client = Client(server, username=username, password=password)
        client.connect()
        scmr = client._service._scmr
        scmr_handle = client._service._scmr_handle

        services = scmr.enum_services_status_w(scmr_handle,
                                               ServiceType.
                                               SERVICE_WIN32_OWN_PROCESS,
                                               EnumServiceState.
                                               SERVICE_STATE_ALL)
        for service in services:
            if service['service_name'].lower().startswith("paexec"):
                paexec_services.append(service['service_name'])

        smb_tree = TreeConnect(client.session,
                               r"\\%s\ADMIN$" % client.connection.server_name)
        smb_tree.connect()

        share = Open(smb_tree, "")
        share.create(ImpersonationLevel.Impersonation,
                     DirectoryAccessMask.FILE_READ_ATTRIBUTES |
                     DirectoryAccessMask.SYNCHRONIZE |
                     DirectoryAccessMask.FILE_LIST_DIRECTORY,
                     FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                     ShareAccess.FILE_SHARE_READ |
                     ShareAccess.FILE_SHARE_WRITE |
                     ShareAccess.FILE_SHARE_DELETE,
                     CreateDisposition.FILE_OPEN,
                     CreateOptions.FILE_DIRECTORY_FILE)
        try:
            paexec_files = share.query_directory("PAExec-*.exe",
                                                 FileInformationClass.
                                                 FILE_NAMES_INFORMATION)
        except SMBResponseException as exc:
            if exc.status != NtStatus.STATUS_NO_SUCH_FILE:
                raise exc
            paexec_files = []

        return client, paexec_services, paexec_files

    def _get_new_generic_client(self, client):
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)
        new_client = Client(client.server, username, password)
        new_client.pid = 1234
        new_client.current_host = "other-host"
        new_client.service_name = "PAExec-%d-%s"\
                                  % (new_client.pid, new_client.current_host)
        new_client._exe_file = "%s.exe" % new_client.service_name
        new_client._service = Service(new_client.service_name,
                                      new_client.session)
        return new_client
