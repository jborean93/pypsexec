# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import pkgutil
import pytest
import uuid

from smbprotocol.connection import (
    Connection,
)

from smbprotocol.session import (
    Session,
)

from smbprotocol.tree import (
    TreeConnect,
)

from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FileAttributes,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)

from pypsexec.exceptions import (
    PDUException,
    PypsexecException,
    SCMRException,
)

from pypsexec.rpc import (
    DataRepresentationFormat,
    FaultPDU,
    ResponsePDU,
)

from pypsexec.scmr import (
    ControlsAccepted,
    CurrentState,
    DesiredAccess,
    EnumServiceState,
    SCMRApi,
    Service,
    ServiceStatus,
    ServiceType,
)


class TestServiceStatus(object):

    def test_create_message(self):
        message = ServiceStatus()
        message["service_type"] = ServiceType.SERVICE_WIN32_OWN_PROCESS
        message["current_state"] = CurrentState.SERVICE_RUNNING
        message["controls_accepted"] = ControlsAccepted.SERVICE_ACCEPT_STOP
        message["win32_exit_code"] = 0
        message["service_specified_exit_code"] = 1
        message["check_point"] = 2
        message["wait_hint"] = 3
        expected = (
            b"\x10\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x03\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_unpack_status(self):
        actual = ServiceStatus()
        data = (
            b"\x10\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x03\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 28
        assert data == b""
        assert (
            actual["service_type"].get_value() == ServiceType.SERVICE_WIN32_OWN_PROCESS
        )
        assert actual["current_state"].get_value() == CurrentState.SERVICE_RUNNING
        assert (
            actual["controls_accepted"].get_value()
            == ControlsAccepted.SERVICE_ACCEPT_STOP
        )
        assert actual["win32_exit_code"].get_value() == 0
        assert actual["service_specified_exit_code"].get_value() == 1
        assert actual["check_point"].get_value() == 2
        assert actual["wait_hint"].get_value() == 3


class TestSCMRApi(object):

    def test_parse_pdu_fine(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        response_pdu = ResponsePDU()
        response_pdu["packed_drep"] = DataRepresentationFormat()
        response_pdu["stub_data"] = b"\x01\x02\x03\x04"
        expected = b"\x01\x02\x03\x04"
        actual = api._parse_pdu(response_pdu.pack(), 10)
        assert actual == expected

    def test_parse_pdu_failure(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        fault_pdu = FaultPDU()
        fault_pdu["packed_drep"] = DataRepresentationFormat()
        with pytest.raises(PDUException) as exc:
            api._parse_pdu(fault_pdu.pack(), 10)
        assert (
            "Expecting ResponsePDU for opnum 10 response but got: "
            "FaultPDU" in str(exc.value)
        )

    def test_parse_error(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        with pytest.raises(SCMRException) as exc:
            api._parse_error(5, "function_name")
        assert (
            str(exc.value) == "Exception calling function_name. Code: 5"
            ", Msg: ERROR_ACCESS_DENIED"
        )

    def test_parse_error_unknown(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)
        with pytest.raises(SCMRException) as exc:
            api._parse_error(999, "function_name")
        assert (
            str(exc.value) == "Exception calling function_name. Code: 999"
            ", Msg: ERROR_UNKNOWN"
        )

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

        expected = (
            b"\x03\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x03\x00\x00\x00"
            b"\x68\x00\x69\x00\x00\x00"
            b"\x00\x00"
        )
        actual = api._marshal_string("hi")
        assert actual == expected

    def test_marshal_string_no_padding(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)

        expected = (
            b"\x02\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x68\x00\x00\x00"
        )
        actual = api._marshal_string("h")
        assert actual == expected

    def test_marshal_string_as_referent(self):
        connection = Connection(uuid.uuid4(), "server", 445)
        session = Session(connection, "user", "password")
        api = SCMRApi(session)

        expected = (
            b"\x00\x00\x00\x01"
            b"\x03\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x03\x00\x00\x00"
            b"\x68\x00\x69\x00\x00\x00"
            b"\x00\x00"
        )
        actual = api._marshal_string("hi", unique=True)
        assert actual == expected


class TestServiceFunctional(object):

    @pytest.fixture(scope="class")
    def session(self):
        server = os.environ.get("PYPSEXEC_SERVER", None)
        username = os.environ.get("PYPSEXEC_USERNAME", None)
        password = os.environ.get("PYPSEXEC_PASSWORD", None)

        if server:
            connection = Connection(uuid.uuid4(), server, 445)
            session = Session(connection, username, password)
            tree = TreeConnect(session, r"\\%s\ADMIN$" % server)
            paexec_file = Open(tree, "PAExec.exe")

            connection.connect()
            try:

                session.connect()
                tree.connect()

                paexec_file.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.FILE_WRITE_DATA,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    ShareAccess.FILE_SHARE_READ,
                    CreateDisposition.FILE_OVERWRITE_IF,
                    CreateOptions.FILE_NON_DIRECTORY_FILE,
                )
                paexec_file.write(pkgutil.get_data("pypsexec", "paexec.exe"), 0)
                paexec_file.close(get_attributes=False)

                yield session
            finally:
                paexec_file.create(
                    ImpersonationLevel.Impersonation,
                    FilePipePrinterAccessMask.DELETE,
                    FileAttributes.FILE_ATTRIBUTE_NORMAL,
                    ShareAccess.FILE_SHARE_DELETE,
                    CreateDisposition.FILE_OVERWRITE_IF,
                    CreateOptions.FILE_DELETE_ON_CLOSE,
                )
                paexec_file.close(get_attributes=False)
                connection.disconnect(True)

        else:
            pytest.skip(
                "PYPSEXEC_SERVER, PYPSEXEC_USERNAME, PYPSEXEC_PASSWORD"
                " environment variables were not set. Integration "
                "tests will be skipped"
            )

    def _create_dummy_stopped_service(self, session):
        service = Service("pypsexectest", session)
        service.open()
        service.create("C:\\Windows\\PAExec.exe -service")
        service.close()
        return service

    def test_open_service_missing(self, session):
        service = Service("missing-service", session)
        service.open()
        assert service._handle is None

        with pytest.raises(PypsexecException) as exc:
            service.start()
        assert (
            str(exc.value) == "Cannot start service missing-service as "
            "it does not exist"
        )

        with pytest.raises(PypsexecException) as exc:
            service.stop()
        assert (
            str(exc.value) == "Cannot stop service missing-service as "
            "it does not exist"
        )
        service.close()

    def test_open_service_existing(self, session):
        service = self._create_dummy_stopped_service(session)
        try:
            service.open()
            service._open_service()
            assert service._handle is not None
        finally:
            service.delete()
            service.close()

    def test_open_service_with_invalid_name(self, session):
        service = Service(b"\x00 a service".decode("utf-8"), session)
        service.open()
        with pytest.raises(SCMRException) as exc:
            service.stop()
        service.close()
        assert (
            str(exc.value) == "Exception calling ROpenServiceW. "
            "Code: 123, Msg: ERROR_INVALID_NAME"
        )

    def test_start_an_already_started_service(self, session):
        service = self._create_dummy_stopped_service(session)
        service.open()

        try:
            service.start()
            service.start()
        finally:
            service.delete()
            service.close()

    def test_manage_dummy_service(self, session):
        service = self._create_dummy_stopped_service(session)
        service.open()
        scmr = service.scmr

        try:
            # test multiple calls to open
            expected = service.scmr_handle
            service.open()
            actual = service.scmr_handle
            assert actual == expected

            # start the test baseline as a stopped service
            service.stop()
            actual = scmr.query_service_status(service._handle)
            assert actual["current_state"].get_value() == CurrentState.SERVICE_STOPPED

            # stop a stopped service
            service.stop()
            actual = scmr.query_service_status(service._handle)
            assert actual["current_state"].get_value() == CurrentState.SERVICE_STOPPED

            # start a stopped service
            service.start()
            actual = scmr.query_service_status(service._handle)
            assert actual["current_state"].get_value() == CurrentState.SERVICE_RUNNING

            # start a started service
            service.start()
            actual = scmr.query_service_status(service._handle)
            assert actual["current_state"].get_value() == CurrentState.SERVICE_RUNNING

            # stop a started service
            service.stop()
            actual = scmr.query_service_status(service._handle)
            assert actual["current_state"].get_value() == CurrentState.SERVICE_STOPPED
        finally:
            service.delete()
            service.close()

    def test_enumerate_services(self, session):
        scmr = SCMRApi(session)
        scmr.open()

        scmr_handle = None
        try:
            scmr_handle = scmr.open_sc_manager_w(
                session.connection.server_name,
                None,
                DesiredAccess.SC_MANAGER_CONNECT
                | DesiredAccess.SC_MANAGER_CREATE_SERVICE
                | DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE,
            )

            types = (
                ServiceType.SERVICE_INTERACTIVE_PROCESS
                | ServiceType.SERVICE_KERNEL_DRIVER
                | ServiceType.SERVICE_WIN32_SHARE_PROCESS
                | ServiceType.SERVICE_WIN32_OWN_PROCESS
                | ServiceType.SERVICE_FILE_SYSTEM_DRIVER
            )
            actual = scmr.enum_services_status_w(
                scmr_handle, types, EnumServiceState.SERVICE_STATE_ALL
            )

            assert len(actual) > 0
            assert isinstance(actual[0]["display_name"], str)
            assert isinstance(actual[0]["service_name"], str)
            assert isinstance(actual[0]["service_status"], ServiceStatus)
        finally:
            if scmr_handle:
                scmr.close_service_handle_w(scmr_handle)
            scmr.close()

    def test_enumerate_services_small_buffer(self, session):
        scmr = SCMRApi(session)
        scmr.open()

        scmr_handle = None
        try:
            scmr_handle = scmr.open_sc_manager_w(
                session.connection.server_name,
                None,
                DesiredAccess.SC_MANAGER_CONNECT
                | DesiredAccess.SC_MANAGER_CREATE_SERVICE
                | DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE,
            )

            actual = scmr.enum_services_status_w(
                scmr_handle,
                ServiceType.SERVICE_INTERACTIVE_PROCESS,
                EnumServiceState.SERVICE_STATE_ALL,
            )
            assert len(actual) > 0
            assert isinstance(actual[0]["display_name"], str)
            assert isinstance(actual[0]["service_name"], str)
            assert isinstance(actual[0]["service_status"], ServiceStatus)
        finally:
            if scmr_handle:
                scmr.close_service_handle_w(scmr_handle)
            scmr.close()
