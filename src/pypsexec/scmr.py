# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging
import struct
import uuid

from collections import (
    OrderedDict,
)

from smbprotocol.connection import (
    NtStatus,
)

from smbprotocol.exceptions import (
    SMBResponseException,
)

from smbprotocol.ioctl import (
    CtlCode,
    IOCTLFlags,
    SMB2IOCTLRequest,
    SMB2IOCTLResponse,
)

from smbprotocol.open import (
    CreateDisposition,
    CreateOptions,
    FilePipePrinterAccessMask,
    ImpersonationLevel,
    Open,
    ShareAccess,
)

from smbprotocol.structure import (
    IntField,
    EnumField,
    FlagField,
    Structure,
)

from smbprotocol.tree import (
    TreeConnect,
)

from pypsexec.exceptions import (
    PypsexecException,
    SCMRException,
)

from pypsexec.rpc import (
    BindAckPDU,
    BindPDU,
    ContextElement,
    DataRepresentationFormat,
    PDUException,
    parse_pdu,
    PFlags,
    RequestPDU,
    ResponsePDU,
    SyntaxIdElement,
)

log = logging.getLogger(__name__)


class ControlCode(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245921.aspx
    """
    SERVICE_CONTROL_CONTINUE = 0x00000003
    SERVICE_CONTROL_INTERROGATE = 0x00000004
    SERVICE_CONTROL_NETBINDADD = 0x00000007
    SERVICE_CONTROL_NETBINDDISABLE = 0x0000000A
    SERVICE_CONTROL_NETBINDENABLE = 0x00000009
    SERVICE_CONTROL_NETBINDREMOVE = 0x00000008
    SERVICE_CONTROL_PARAMCHANGE = 0x00000006
    SERVICE_CONTROL_PAUSE = 0x00000002
    SERVICE_CONTROL_STOP = 0x00000001


class DesiredAccess(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245853.aspx
    """
    DELETE = 0x00010000
    READ_CONTROL = 0x00020000
    WRITE_DAC = 0x00040000
    WRITE_OWNER = 0x00080000
    SERVICE_ALL_ACCESS = 0x000F01FF
    SERVICE_CHANGE_CONFIG = 0x00000002
    SERVICE_ENUMERATE_DEPENDENTS = 0x00000008
    SERVICE_INTERROGATE = 0x00000080
    SERVICE_PAUSE_CONTINUE = 0x00000040
    SERVICE_QUERY_CONFIG = 0x00000001
    SERVICE_QUERY_STATUS = 0x00000004
    SERVICE_START = 0x00000010
    SERVICE_STOP = 0x00000020
    SERVICE_USER_DEFINED_CONTROL = 0x00000100
    SERVICE_SET_STATUS = 0x00008000
    SC_MANAGER_LOCK = 0x00000008
    SC_MANAGER_CREATE_SERVICE = 0x00000002
    SC_MANAGER_ENUMERATE_SERVICE = 0x00000004
    SC_MANAGER_CONNECT = 0x00000001
    SC_MANAGER_QUERY_LOCK_STATUS = 0x00000010
    SC_MANAGER_MODIFY_BOOT_CONFIG = 0x00000020


class ServiceType(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245925.aspx
    dwServiceType
    flags
    """
    SERVICE_KERNEL_DRIVER = 0x00000001
    SERVICE_FILE_SYSTEM_DRIVER = 0x00000002
    SERVICE_WIN32_OWN_PROCESS = 0x00000010
    SERVICE_WIN32_SHARE_PROCESS = 0x00000020
    SERVICE_INTERACTIVE_PROCESS = 0x00000100


class StartType(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245925.aspx
    dwStartType
    enum
    """
    SERVICE_BOOT_START = 0x00000000
    SERVICE_SYSTEM_START = 0x00000001
    SERVICE_AUTO_START = 0x00000002
    SERVICE_DEMAND_START = 0x00000003
    SERVICE_DISABLED = 0x00000004


class ErrorControl(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245925.aspx
    dwErrorControl
    enum
    """
    SERVICE_ERROR_IGNORE = 0x00000000
    SERVICE_ERROR_NORMAL = 0x00000001
    SERVICE_ERROR_SEVERE = 0x00000002
    SERVICE_ERROR_CRITICAL = 0x00000003


class CurrentState(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245911.aspx
    dwCurrentState
    enum
    """
    SERVICE_CONTINUE_PENDING = 0x00000005
    SERVICE_PAUSE_PENDING = 0x00000006
    SERVICE_PAUSED = 0x00000007
    SERVICE_RUNNING = 0x00000004
    SERVICE_START_PENDING = 0x00000002
    SERVICE_STOP_PENDING = 0x00000003
    SERVICE_STOPPED = 0x00000001


class ControlsAccepted(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245911.aspx
    dwControlsAccepted
    flags
    """
    SERVICE_ACCEPT_PARAMCHANGE = 0x00000008
    SERVICE_ACCEPT_PAUSE_CONTINUE = 0x00000002
    SERVICE_ACCEPT_SHUTDOWN = 0x00000004
    SERVICE_ACCEPT_STOP = 0x00000001
    SERVICE_ACCEPT_HARDWAREPROFILECHANGE = 0x00000020
    SERVICE_ACCEPT_POWEREVENT = 0x00000040
    SERVICE_ACCEPT_SESSIONCHANGE = 0x00000080
    SERVICE_ACCEPT_PRESHUTDOWN = 0x00000100
    SERVICE_ACCEPT_TIMECHANGE = 0x00000200
    SERVICE_ACCEPT_TRIGGEREVENT = 0x00000400


class EnumServiceState(object):
    """
    https://msdn.microsoft.com/en-us/library/cc245933.aspx
    dwServiceState
    Specifies the service records to enumerate
    """
    SERVICE_ACTIVE = 0x00000001
    SERVICE_INACTIVE = 0x00000002
    SERVICE_STATE_ALL = 0x00000003


class ScmrReturnValues(object):
    # The return values a RPC request can return
    ERROR_SUCCESS = 0
    ERROR_SUCCESS_NOTIFY_CHANGED = 0xFE75FFFF
    ERROR_SUCCESS_LAST_NOTIFY_CHANGED = 0xFD75FFFF
    ERROR_FILE_NOT_FOUND = 2
    ERROR_PATH_NOT_FOUND = 3
    ERROR_ACCESS_DENIED = 5
    ERROR_INVALID_HANDLE = 6
    ERROR_INVALID_DATA = 13
    ERROR_INVALID_PARAMETER = 87
    ERROR_INVALID_NAME = 123
    ERROR_MORE_DATA = 234
    ERROR_DEPENDENT_SERVICES_RUNNING = 1051
    ERROR_INVALID_SERVICE_CONTROL = 1052
    ERROR_SERVICE_REQUEST_TIMEOUT = 1053
    ERROR_SERVICE_NO_THREAD = 1054
    ERROR_SERVICE_DATABASE_LOCKED = 1055
    ERROR_SERVICE_ALREADY_RUNNING = 1056
    ERROR_INVALID_SERVICE_ACCOUNT = 1057
    ERROR_SERVICE_DISABLED = 1058
    ERROR_CIRCULAR_DEPENDENCY = 1059
    ERROR_SERVICE_DOES_NOT_EXIST = 1060
    ERROR_SERVICE_CANNOT_ACCEPT_CTRL = 1061
    ERROR_SERVICE_NOT_ACTIVE = 1062
    ERROR_DATABASE_DOES_NOT_EXIST = 1065
    ERROR_SERVICE_DEPENDENCY_FAIL = 1068
    ERROR_SERVICE_LOGON_FAILED = 1069
    ERROR_SERVICE_MARKED_FOR_DELETE = 1072
    ERROR_SERVICE_EXISTS = 1073
    ERROR_SERVICE_DEPENDENCY_DELETED = 1075
    ERROR_DUPLICATE_SERVICE_NAME = 1078
    ERROR_SHUTDOWN_IN_PROGRESS = 1115


class ServiceStatus(Structure):
    """
    [MS-SCMR] 2.2.47 SERVICE_STATUS
    https://msdn.microsoft.com/en-us/library/cc245911.aspx

    Defines Information about a service
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('service_type', FlagField(
                size=4,
                flag_type=ServiceType,
                flag_strict=False
            )),
            ('current_state', EnumField(
                size=4,
                enum_type=CurrentState
            )),
            ('controls_accepted', FlagField(
                size=4,
                flag_type=ControlsAccepted,
                flag_strict=False
            )),
            ('win32_exit_code', IntField(size=4)),
            ('service_specified_exit_code', IntField(size=4)),
            ('check_point', IntField(size=4)),
            ('wait_hint', IntField(size=4))
        ])
        super(ServiceStatus, self).__init__()


class Service(object):

    def __init__(self, name, smb_session):
        """
        Higher-level interface over SCMR to manage Windows services. This is
        customised for the PAExec service to really just be used in that
        scenario.

        :param name: The name of the service
        :param smb_session: A connected SMB Session that can be used to connect
            to the IPC$ tree.
        """
        self.name = name
        self.smb_session = smb_session

        self._handle = None
        self._scmr = None
        self._scmr_handle = None

    def open(self):
        if self._scmr:
            log.debug("Handle for SCMR on %s is already open"
                      % self.smb_session.connection.server_name)
            return

        # connect to the SCMR Endpoint
        log.info("Opening handle for SCMR on %s"
                 % self.smb_session.connection.server_name)
        self._scmr = SCMRApi(self.smb_session)
        self._scmr.open()
        self._scmr_handle = self._scmr.open_sc_manager_w(
            self.smb_session.connection.server_name,
            None,
            DesiredAccess.SC_MANAGER_CONNECT |
            DesiredAccess.SC_MANAGER_CREATE_SERVICE |
            DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE
        )

    def close(self):
        if self._handle:
            log.info("Closing Service handle for service %s" % self.name)
            self._scmr.close_service_handle_w(self._handle)
            self._handle = None

        if self._scmr_handle:
            log.info("Closing SCMR handle")
            self._scmr.close_service_handle_w(self._scmr_handle)
            self._scmr_handle = None

        if self._scmr:
            log.info("Closing bindings for SCMR")
            self._scmr.close()
            self._scmr = None

    def start(self):
        self._open_service()
        if self._handle is None:
            raise PypsexecException("Cannot start service %s as it does not "
                                    "exist" % self.name)

        try:
            self._scmr.start_service_w(self._handle)
        except SCMRException as exc:
            if exc.return_code != \
                    ScmrReturnValues.ERROR_SERVICE_ALREADY_RUNNING:
                raise exc

    def stop(self):
        self._open_service()
        if self._handle is None:
            raise PypsexecException("Cannot stop service %s as it does not "
                                    "exist" % self.name)

        try:
            self._scmr.control_service(self._handle,
                                       ControlCode.SERVICE_CONTROL_STOP)
        except SCMRException as exc:
            if exc.return_code != ScmrReturnValues.ERROR_SERVICE_NOT_ACTIVE:
                raise exc

    def create(self, path):
        self._open_service()
        if self._handle:
            return

        self._handle = self._scmr.create_service_w(
            self._scmr_handle,
            self.name,
            self.name,
            DesiredAccess.SERVICE_QUERY_STATUS | DesiredAccess.SERVICE_START |
            DesiredAccess.SERVICE_STOP | DesiredAccess.DELETE,
            ServiceType.SERVICE_WIN32_OWN_PROCESS,
            StartType.SERVICE_DEMAND_START,
            ErrorControl.SERVICE_ERROR_NORMAL,
            path,
            None,
            0,
            None,
            None,
            None
        )[1]

    def delete(self):
        self._open_service()
        if self._handle is None:
            return

        self.stop()
        self._scmr.delete_service(self._handle)

    def _open_service(self):
        if self._handle:
            return self._handle

        # connect to the desired service in question
        desired_access = DesiredAccess.SERVICE_QUERY_STATUS | \
            DesiredAccess.SERVICE_START | \
            DesiredAccess.SERVICE_STOP | \
            DesiredAccess.DELETE
        try:
            log.info("Opening handle for Service %s" % self.name)
            self._handle = self._scmr.open_service_w(self._scmr_handle,
                                                     self.name,
                                                     desired_access)
        except SCMRException as exc:
            if exc.return_code != \
                    ScmrReturnValues.ERROR_SERVICE_DOES_NOT_EXIST:
                raise exc
            else:
                log.debug("Could not open handle for service %s as it did "
                          "not exist" % self.name)


class SCMRApi(object):

    def __init__(self, smb_session):
        # connect to the IPC tree and open a handle at svcctl
        self.tree = TreeConnect(smb_session, r"\\%s\IPC$"
                                % smb_session.connection.server_name)
        self.handle = Open(self.tree, "svcctl")
        self.call_id = 0

    def open(self):
        log.debug("Connecting to SMB Tree %s for SCMR" % self.tree.share_name)
        self.tree.connect()

        log.debug("Opening handle to svcctl pipe")
        self.handle.create(ImpersonationLevel.Impersonation,
                           FilePipePrinterAccessMask.GENERIC_READ |
                           FilePipePrinterAccessMask.GENERIC_WRITE,
                           0,
                           ShareAccess.FILE_SHARE_READ |
                           ShareAccess.FILE_SHARE_WRITE |
                           ShareAccess.FILE_SHARE_DELETE,
                           CreateDisposition.FILE_OPEN,
                           CreateOptions.FILE_NON_DIRECTORY_FILE)

        # we need to bind svcctl to SCManagerW over DCE/RPC
        bind = BindPDU()
        bind['pfx_flags'].set_flag(PFlags.PFC_FIRST_FRAG)
        bind['pfx_flags'].set_flag(PFlags.PFC_LAST_FRAG)
        bind['packed_drep'] = DataRepresentationFormat()
        bind['call_id'] = self.call_id
        self.call_id += 1

        context_ndr = ContextElement()
        context_ndr['context_id'] = 0
        context_ndr['abstract_syntax'] = SyntaxIdElement()
        context_ndr['abstract_syntax']['uuid'] = \
            uuid.UUID("367ABB81-9844-35F1-AD32-98F038001003")
        context_ndr['abstract_syntax']['version'] = 2

        # https://msdn.microsoft.com/en-us/library/cc243843.aspx
        ndr_syntax = SyntaxIdElement()
        ndr_syntax['uuid'] = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
        ndr_syntax['version'] = 2
        context_ndr['transfer_syntaxes'] = [
            ndr_syntax
        ]

        context_bind = ContextElement()
        context_bind['context_id'] = 1
        context_bind['abstract_syntax'] = SyntaxIdElement()
        context_bind['abstract_syntax']['uuid'] = \
            uuid.UUID("367ABB81-9844-35F1-AD32-98F038001003")
        context_bind['abstract_syntax']['version'] = 2

        # https://msdn.microsoft.com/en-us/library/cc243715.aspx
        # uuid prefix = 6CB71C2C-9812-4540
        # uuid prefix bytes = b'\x2c\x1c\xb7\x6c\x12\x98\x40\x45'
        # BindTimeFeatureNegotiateBitmask
        # https://msdn.microsoft.com/en-us/library/cc243884.aspx
        # SecurityContextMultiplexingSupported = 0x01
        # KeepConnectionOnOrphanSupported = 0x02
        # version number is 1
        bind_syntax = SyntaxIdElement()
        bind_syntax['uuid'] = b'\x2c\x1c\xb7\x6c\x12\x98\x40\x45' \
                              b'\x03\x00\x00\x00\x00\x00\x00\x00'
        bind_syntax['version'] = 1
        context_bind['transfer_syntaxes'] = [
            bind_syntax
        ]

        bind['context_elems'] = [
            context_ndr,
            context_bind
        ]
        bind_data = bind.pack()

        log.info("Sending bind request to svcctl")
        log.debug(str(bind))
        self.handle.write(bind_data)

        log.info("Receiving bind result for svcctl")
        bind_data = self.handle.read(0, 1024)
        bind_result = parse_pdu(bind_data)
        log.debug(str(bind_result))
        if not isinstance(bind_result, BindAckPDU):
            raise PDUException("Expecting BindAckPDU for initial bind result "
                               "but got: %s" % str(bind_result))

    def close(self):
        log.info("Closing bind to svcctl")
        self.handle.close(False)
        self.tree.disconnect()

    # SCMR Functions below

    def close_service_handle_w(self, handle):
        # https://msdn.microsoft.com/en-us/library/cc245920.aspx
        opnum = 0

        res = self._invoke("RCloseServiceHandleW", opnum, handle)
        handle = res[:20]
        return_code = struct.unpack("<i", res[20:])[0]
        self._parse_error(return_code, "RCloseServiceHandleW")
        return handle

    def control_service(self, service_handle, control_code):
        # https://msdn.microsoft.com/en-us/library/cc245921.aspx
        opnum = 1

        data = service_handle
        data += struct.pack("<i", control_code)

        res = self._invoke("RControlService", opnum, data)
        return_code = struct.unpack("<i", res[-4:])[0]
        self._parse_error(return_code, "RControlService")

        service_status = ServiceStatus()
        service_status.unpack(res[:-4])

        return service_status

    def delete_service(self, service_handle):
        # https://msdn.microsoft.com/en-us/library/cc245926.aspx
        opnum = 2

        res = self._invoke("RDeleteService", opnum, service_handle)
        return_code = struct.unpack("<i", res)[0]
        self._parse_error(return_code, "RDeleteService")

    def query_service_status(self, service_handle):
        # https://msdn.microsoft.com/en-us/library/cc245952.aspx
        opnum = 6

        res = self._invoke("RQueryServiceStatus", opnum, service_handle)
        return_code = struct.unpack("<i", res[-4:])[0]
        self._parse_error(return_code, "RQueryServiceStatus")

        service_status = ServiceStatus()
        service_status.unpack(res[:-4])

        return service_status

    def enum_services_status_w(self, server_handle, service_type,
                               service_state):
        """
        Enumerates the services based on the criteria selected

        :param server_handle: A handle to SCMR
        :param service_type: ServiceType flags to filter by service type
        :param service_state: EnumServiceState enum value
        :return: List dictionaries with the following entries
            service_name: The service name of the service
            display_name: The display name of the service
            service_status: ServiceStatus structure of the service
        """
        # https://msdn.microsoft.com/en-us/library/cc245933.aspx
        opnum = 14

        # sent 0 bytes on the buffer size for the 1st request to get the
        # buffer size that is required
        req_data = server_handle
        req_data += struct.pack("<i", service_type)
        req_data += struct.pack("<i", service_state)
        req_data += struct.pack("<i", 0)
        req_data += b"\x00\x00\x00\x00"
        res = self._invoke("REnumServicesStatusW", opnum, req_data)

        # now send another request with the total buffer size sent
        buffer_size = struct.unpack("<i", res[4:8])[0]
        req_data = server_handle
        req_data += struct.pack("<i", service_type)
        req_data += struct.pack("<i", service_state)
        req_data += res[4:8]
        req_data += b"\x00\x00\x00\x00"

        try:
            res = self._invoke("REnumServicesStatusW", opnum, req_data)
            data = res
        except SMBResponseException as exc:
            if exc.status != NtStatus.STATUS_BUFFER_OVERFLOW:
                raise exc

            ioctl_resp = SMB2IOCTLResponse()
            ioctl_resp.unpack(exc.header['data'].get_value())
            pdu_resp = self._parse_pdu(ioctl_resp['buffer'].get_value(), opnum)
            read_data = self.handle.read(0, 3256)  # 4280 - 1024
            data = pdu_resp + read_data

        while len(data) < buffer_size:
            read_data = self.handle.read(0, 4280)
            data += self._parse_pdu(read_data, opnum)

        return_code = struct.unpack("<i", data[-4:])[0]
        self._parse_error(return_code, "REnumServicesStatusW")

        def extract_unicode(buffer):
            # https://github.com/jborean93/pypsexec/issues/36
            # When ending with ASCII chars the 2nd byte is 00.
            null_idx = buffer.index(b"\x00\x00")
            null_idx += null_idx % 2
            return buffer[:null_idx].decode('utf-16-le')

        # now we have all the data, let's unpack it
        services = []
        services_returned = struct.unpack("<i", data[-12:-8])[0]
        offset = 4
        for i in range(0, services_returned):
            name_offset = struct.unpack("<i", data[offset:4 + offset])[0]
            disp_offset = struct.unpack("<i", data[4 + offset:8 + offset])[0]
            service_status = ServiceStatus()
            service_name = extract_unicode(data[name_offset + 4:])
            display_name = extract_unicode(data[disp_offset + 4:])
            service_status.unpack(data[offset + 8:])

            service_info = {
                "display_name": display_name,
                "service_name": service_name,
                "service_status": service_status
            }
            services.append(service_info)
            offset += 8 + len(service_status)

        return services

    def open_sc_manager_w(self, machine_name, database_name, desired_access):
        # https://msdn.microsoft.com/en-us/library/cc245942.aspx
        opnum = 15

        data = self._marshal_string(machine_name, unique=True)
        data += self._marshal_string(database_name)
        data += struct.pack("<i", desired_access)

        res = self._invoke("ROpenSCManagerW", opnum, data)
        server_handle = res[:20]
        return_code = struct.unpack("<i", res[20:])[0]
        self._parse_error(return_code, "ROpenSCManagerW")
        return server_handle

    def open_service_w(self, server_handle, service_name, desired_access):
        # https://msdn.microsoft.com/en-us/library/cc245944.aspx
        opnum = 16

        data = server_handle
        data += self._marshal_string(service_name)
        data += struct.pack("<i", desired_access)

        res = self._invoke("ROpenServiceW", opnum, data)
        service_handle = res[:20]
        return_code = struct.unpack("<i", res[20:])[0]
        self._parse_error(return_code, "ROpenServiceW")
        return service_handle

    def start_service_w(self, service_handle, *args):
        opnum = 19

        data = service_handle
        data += struct.pack("<i", len(args))
        data += b"".join([self._marshal_string(arg) for arg in args])
        data += b"\x00" * 4  # terminate arg list

        res = self._invoke("RStartServiceW", opnum, data)
        return_code = struct.unpack("<i", res)[0]
        self._parse_error(return_code, "RStartServiceW")

    def create_service_w(self, server_handle, service_name, display_name, desired_access, service_type, start_type,
                         error_control, path, load_order_group, tag_id, dependencies, username, password):
        # https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-scmr/6a8ca926-9477-4dd4-b766-692fab07227e
        opnum = 12

        data = server_handle
        data += self._marshal_string(service_name)
        data += self._marshal_string(display_name, unique=True)
        data += struct.pack("<i", desired_access)
        data += struct.pack("<i", service_type)
        data += struct.pack("<i", start_type)
        data += struct.pack("<i", error_control)
        data += self._marshal_string(path)
        data += self._marshal_string(load_order_group)
        data += struct.pack("<i", tag_id)

        # TODO: convert list of string to a byte object
        dependencies_bytes = dependencies if dependencies else b"\x00" * 6
        data += dependencies_bytes
        dependencies_length = len(dependencies) if dependencies else 0
        data += struct.pack("<i", dependencies_length)

        data += self._marshal_string(username)

        pass_bytes = self._marshal_string(password)
        data += pass_bytes
        pass_len = len(pass_bytes) if password else 0
        data += struct.pack("<i", pass_len)

        res = self._invoke("RCreateServiceW", opnum, data)
        tag_id = res[0:4]
        service_handle = res[4:24]
        return_code = struct.unpack("<i", res[24:])[0]
        self._parse_error(return_code, "RCreateServiceW")
        return tag_id, service_handle

    def _invoke(self, function_name, opnum, data):
        req = RequestPDU()
        req['pfx_flags'].set_flag(PFlags.PFC_FIRST_FRAG)
        req['pfx_flags'].set_flag(PFlags.PFC_LAST_FRAG)
        req['packed_drep'] = DataRepresentationFormat()
        req['call_id'] = self.call_id
        self.call_id += 1

        req['opnum'] = opnum
        req['stub_data'] = data

        ioctl_request = SMB2IOCTLRequest()
        ioctl_request['ctl_code'] = CtlCode.FSCTL_PIPE_TRANSCEIVE
        ioctl_request['file_id'] = self.handle.file_id
        ioctl_request['max_output_response'] = 1024
        ioctl_request['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL
        ioctl_request['buffer'] = req

        session_id = self.tree.session.session_id
        tree_id = self.tree.tree_connect_id
        log.info("Sending svcctl RPC request for %s" % function_name)
        log.debug(str(req))
        request = self.tree.session.connection.send(ioctl_request,
                                                    sid=session_id,
                                                    tid=tree_id)
        log.info("Receiving svcctl RPC response for %s" % function_name)
        resp = self.tree.session.connection.receive(request)
        ioctl_resp = SMB2IOCTLResponse()
        ioctl_resp.unpack(resp['data'].get_value())
        log.debug(str(ioctl_resp))

        pdu_resp = self._parse_pdu(ioctl_resp['buffer'].get_value(), opnum)
        return pdu_resp

    def _parse_pdu(self, data, opnum):
        pdu_resp = parse_pdu(data)
        if not isinstance(pdu_resp, ResponsePDU):
            raise PDUException("Expecting ResponsePDU for opnum %d response "
                               "but got: %s" % (opnum, str(pdu_resp)))
        return pdu_resp['stub_data'].get_value()

    def _parse_error(self, return_code, function_name):
        error_string = "ERROR_UNKNOWN"
        for error_name, error_val in vars(ScmrReturnValues).items():
            if isinstance(error_val, int) and error_val == return_code:
                error_string = error_name
                break
        if not error_string.startswith("ERROR_SUCCESS"):
            raise SCMRException(function_name, return_code, error_string)

    def _marshal_string(self, string, unique=False, max_count=None):
        """
        Strings are encoding as a UTF-16-LE byte structure and are marshalled
        in a particular format to send over RPC. The format is as follows

            Referent ID (Int32): A unique ID for the string, we just set to 1
            Max Count (Int32): If the server can return a value, this is the
                size that can be returned in the buffer otherwise just the
                numbers of chars in the input string
            Offset (Int32): The offset of the string, defaults to 0
            Actual Count (Int32): The number of chars (not bytes) or the string
                itself including the NULL terminator
            Bytes (Bytes): The string encoded as a UTF-16-LE byte string with
                a NULL terminator
            Padding (Bytes): The value must align to a 4-byte boundary so this
                is some NULL bytes to pad the length

        :param string: The string to marshal
        :param unique: Whether the string is unique and requires an ID
        :return: A byte string of the marshaled string
        """
        # return NULL Pointer for a null string
        if not string:
            return b"\x00" * 4

        referent = b"\x00\x00\x00\x01" if unique else b""
        unicode_string = string.encode("utf-16-le") + b"\x00\x00"
        unicode_count = int(len(unicode_string) / 2)
        count = struct.pack("<i", unicode_count)
        offset = b"\x00" * 4
        bytes = referent + count + offset + count + unicode_string

        # each parameter needs to be aligned at a 4-byte boundary so get the
        # padding length if necessary
        mod = len(bytes) % 4
        padding_len = 0 if mod == 0 else 4 - mod
        return bytes + (b"\x00" * padding_len)
