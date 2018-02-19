import binascii
import os
import uuid

import pytest

from smbprotocol.connection import Connection
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.open import CreateDisposition, CreateOptions, \
    FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel, Open, \
    ShareAccess

from pypsexec.exceptions import SCMRException
from pypsexec.paexec import PAEXEC_DATA
from pypsexec.scmr import ControlsAccepted, CurrentState, SCMRApi, Service, \
    ServiceStatus, ServiceType


class TestServiceStatus(object):

    def test_create_message(self):
        message = ServiceStatus()
        message['service_type'] = ServiceType.SERVICE_WIN32_OWN_PROCESS
        message['current_state'] = CurrentState.SERVICE_RUNNING
        message['controls_accepted'] = ControlsAccepted.SERVICE_ACCEPT_STOP
        message['win32_exit_code'] = 0
        message['service_specified_exit_code'] = 1
        message['check_point'] = 2
        message['wait_hint'] = 3
        expected = b"\x10\x00\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x02\x00\x00\x00" \
                   b"\x03\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_unpack_status(self):
        actual = ServiceStatus()
        data = b"\x10\x00\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x02\x00\x00\x00" \
               b"\x03\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 28
        assert data == b""
        assert actual['service_type'].get_value() == \
            ServiceType.SERVICE_WIN32_OWN_PROCESS
        assert actual['current_state'].get_value() == \
            CurrentState.SERVICE_RUNNING
        assert actual['controls_accepted'].get_value() == \
            ControlsAccepted.SERVICE_ACCEPT_STOP
        assert actual['win32_exit_code'].get_value() == 0
        assert actual['service_specified_exit_code'].get_value() == 1
        assert actual['check_point'].get_value() == 2
        assert actual['wait_hint'].get_value() == 3


class TestSCMRApi(object):

    def test_parse_error(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        with pytest.raises(SCMRException) as exc:
            api._parse_error(0, {0: "ERROR_TEST"}, "function_name")
        assert str(exc.value) == "Exception calling function_name. Code: 0, " \
                                 "Msg: ERROR_TEST"

    def test_parse_error_unknown(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        with pytest.raises(SCMRException) as exc:
            api._parse_error(1, {0: "ERROR_TEST"}, "function_name")
        assert str(exc.value) == "Exception calling function_name. Code: 1, " \
                                 "Msg: ERROR_UNKNOWN"

    def test_marshal_string_none(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)

        expected = b"\x00\x00\x00\x00"
        actual = api._marshal_string(None)
        assert actual == expected

    def test_marshal_string(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)

        expected = b"\x03\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x68\x00\x69\x00\x00\x00"
        actual = api._marshal_string("hi")
        assert actual == expected

    def test_marshal_string_as_referent(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)

        expected = b"\x00\x00\x00\x01" \
                   b"\x03\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x03\x00\x00\x00" \
                   b"\x68\x00\x69\x00\x00\x00"
        actual = api._marshal_string("hi", referent_required=True)
        assert actual == expected


class TestServiceFunctional(object):

    @pytest.fixture(scope='class')
    def session(self):
        server = os.environ.get('PYPSEXEC_SERVER', None)
        username = os.environ.get('PYPSEXEC_USERNAME', None)
        password = os.environ.get('PYPSEXEC_PASSWORD', None)

        if server and username and password:
            connection = Connection(uuid.uuid4(), server, 445)
            session = Session(connection, username, password)
            tree = TreeConnect(session, r"\\%s\ADMIN$" % server)
            paexec_file = Open(tree, "PAExec.exe")

            connection.connect()
            try:

                session.connect()
                tree.connect()

                paexec_file.open(ImpersonationLevel.Impersonation,
                                 FilePipePrinterAccessMask.FILE_WRITE_DATA,
                                 FileAttributes.FILE_ATTRIBUTE_NORMAL,
                                 ShareAccess.FILE_SHARE_READ,
                                 CreateDisposition.FILE_OVERWRITE_IF,
                                 CreateOptions.FILE_NON_DIRECTORY_FILE)
                paexec_file.write(binascii.unhexlify(PAEXEC_DATA), 0)
                paexec_file.close(get_attributes=False)

                yield session
            finally:
                paexec_file.open(ImpersonationLevel.Impersonation,
                                 FilePipePrinterAccessMask.DELETE,
                                 FileAttributes.FILE_ATTRIBUTE_NORMAL,
                                 0,
                                 CreateDisposition.FILE_OVERWRITE_IF,
                                 CreateOptions.FILE_DELETE_ON_CLOSE)
                paexec_file.close(get_attributes=False)
                connection.disconnect(True)

        else:
            pytest.skip("PYPSEXEC_SERVER, PYPSEXEC_USERNAME, PYPSEXEC_PASSWORD"
                        " environment variables were not set. Integration "
                        "tests will be skipped")

    def test_open_service_missing(self, session):
        service = Service("missing-service", session)
        service.open()
        assert not service.exists
        assert service.status is None
        service.close()

    def test_open_service_existing(self, session):
        service = Service("netlogon", session)
        service.open()
        assert service.exists
        assert service.status == "running"

        # open it one more time to make sure it doesn't fail
        service.open()
        assert service.exists
        assert service.status == "running"

        service.close()

    def test_open_service_with_invalid_name(self, session):
        service = Service(b"\x00 a service".decode('utf-8'), session)
        with pytest.raises(SCMRException) as exc:
            service.open()
        service.close()
        assert str(exc.value) == "Exception calling ROpenServiceW. " \
                                 "Code: 123, Msg: ERROR_INVALID_NAME"

    def test_refresh_service_without_an_open(self, session):
        service = Service("netlogon", session)
        assert service.exists is None
        assert service.status is None
        service.refresh()
        assert service.exists
        assert service.status == "running"
        service.close()

    def test_refresh_service_that_does_not_exist(self, session):
        service = Service("missing-service", session)
        service.open()
        assert not service.exists
        service.refresh()
        assert not service.exists
        service.close()

    def test_start_an_already_started_service(self, session):
        service = Service("netlogon", session)
        service.open()
        assert service.status == "running"
        service.start()
        assert service.status == "running"
        service.close()

    def test_create_dummy_service(self, session):
        service = Service("pypsexectest", session)
        service.open()
        service.create("C:\\Windows\\PAExec.exe -service")
        try:
            service.refresh()
            assert service.exists
            assert service.status == "stopped"

            # start the service
            service.start()
            assert service.status == "running"

            # stop the service
            service.stop()
            assert service.status == "stopped"

            # test out stopping an already stopped service
            service.stop()
            assert service.status == "stopped"
        finally:
            service.delete()
            service.close()
