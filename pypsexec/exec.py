import socket
import struct
import time
import uuid

from pypsexec.exceptions import SCMRException
from pypsexec.paexec import paexec_out_stream, get_unique_id, \
    PAExecSettingsBuffer, PAExecSettingsMsg, PAExecMsgId, PAExecMsg, \
    PAExecReturnBuffer, PAExecStartBuffer
from pypsexec.scmr import SCMRApi, DesiredAccess, ServiceType, \
    ErrorControl, StartType, CurrentState, ControlCode
from smbprotocol.connection import Connection
from smbprotocol.constants import FilePipePrinterAccessMask, \
    FileAttributes, ImpersonationLevel, CreateOptions, CreateDisposition, \
    ShareAccess, CtlCode, IOCTLFlags, Commands, NtStatus
from smbprotocol.open import Open
from smbprotocol.messages import SMB2IOCTLRequest, SMB2ReadResponse
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect
from smbprotocol.exceptions import SMBResponseException

try:
    from collections import OrderedDict
except ImportError:
    from ordereddict import OrderedDict

from multiprocessing.dummy import Pool, Process, Queue, Pipe, Lock
from queue import Empty


def ioctl_pipe(tree, name):
    ioctl_request = SMB2IOCTLRequest()
    ioctl_request['ctl_code'] = CtlCode.FSCTL_PIPE_WAIT
    ioctl_request['file_id'] = b"\xff" * 16
    ioctl_request['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

    # https://msdn.microsoft.com/en-us/library/cc232126.aspx
    pipe_data = b"\x00" * 8
    pipe_data +=  struct.pack("<i", len(name) * 2)
    pipe_data += b"\x00"
    pipe_data += b"\x00"
    pipe_data += name.encode('utf-16-le')

    ioctl_request['buffer'] = pipe_data

    header = tree.session.connection.send(ioctl_request, Commands.SMB2_IOCTL,
                                          tree.session,
                                          tree)
    resp = tree.session.connection.receive(
        header['message_id'].get_value()
    )


def create_pipe(tree, name, access_mask):
    pipe = Open(tree, name)
    pipe.open(ImpersonationLevel.Impersonation,
              access_mask,
              FileAttributes.FILE_ATTRIBUTE_NORMAL,
              ShareAccess.FILE_SHARE_READ |
              ShareAccess.FILE_SHARE_WRITE |
              ShareAccess.FILE_SHARE_DELETE,
              CreateDisposition.FILE_OPEN,
              CreateOptions.FILE_NON_DIRECTORY_FILE |
              CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT)
    return pipe


def read_pipe(pipe, queue):
    sent_first = False
    while True:
        # keep on trying to get the pipe output until we receive a
        # STATUS_PIPE_BROKEN
        pending_id = None
        try:
            data = pipe.read(0, 255)
            if not sent_first:
                queue.put(None)  # tells parent thread to read from main pipe
                sent_first = True
            queue.put(data)
        except SMBResponseException as exc:
            if not sent_first:
                queue.put(None)
                sent_first = True
            if exc.status == NtStatus.STATUS_PENDING:
                # need to poll the receive queue for the final message
                pending_id = exc.message_id
            elif exc.status == NtStatus.STATUS_PIPE_BROKEN:
                break
            else:
                raise exc

        if pending_id:
            try:
                a = pipe.connection.receive(pending_id)
            except SMBResponseException as exc:
                if exc.status == NtStatus.STATUS_PIPE_BROKEN:
                    break
                else:
                    raise exc

            read_resp = SMB2ReadResponse()
            read_resp.unpack(a['data'].get_value())
            queue.put(read_resp['buffer'].get_value())


def get_buffer(resp):
    read_resp = SMB2ReadResponse()
    read_resp.unpack(resp['data'].get_value())
    return read_resp['buffer'].get_value()


# set exe variables
#server = "DC01.domain.local"
server = "192.168.56.10"
port = 445
username = "vagrant-domain@DOMAIN.LOCAL"
password = "VagrantPass1"
#pid = os.getpid()
pid = 6632
current_host = socket.gethostname().upper().replace("-", "").replace("_", "")
#current_host = "DC01"
paexec_id = get_unique_id(pid, current_host)
exe = "powershell.exe"
#arguments = "/c echo hello world, my name is Jordan."
#arguments = "Write-Host hello world; Start-Sleep -Seconds 10; Write-Host another hello; Write-Error hell"
arguments = "Write-Host hello world; Start-Sleep -Seconds 5; Write-Host another hello; Write-Error hell"

svc_name = "PAExec-%d-%s" % (pid, current_host)

exe_payload = paexec_out_stream
exe_path = "%s.exe" % svc_name

# Setup SMB connection and session
guid = uuid.uuid4()

connection = Connection(guid, server, port, require_signing=True)
try:
    connection.connect()

    session = Session(connection, username, password, require_encryption=False)
    session.connect()

    # open the service manager
    scmr_api = SCMRApi(session)
    scmr_api.open()

    try:
        sc_desired_access = DesiredAccess.SC_MANAGER_CONNECT | \
                            DesiredAccess.SC_MANAGER_CREATE_SERVICE | \
                            DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE
        scm_handle = scmr_api.open_sc_manager_w(server, None, sc_desired_access)

        try:
            svc_desired_access = DesiredAccess.SERVICE_QUERY_STATUS | \
                                 DesiredAccess.SERVICE_START | \
                                 DesiredAccess.SERVICE_STOP | \
                                 DesiredAccess.DELETE

            # delete and create a brand new service
            try:
                service_handle = scmr_api.open_service_w(scm_handle, svc_name,
                                                         svc_desired_access)
            except SCMRException as exc:
                # check the return code wasn't service does not exist
                if exc.return_code != 1060:
                    raise exc
            else:
                # delete the service as it already exists
                service_status = scmr_api.query_service_status(service_handle)
                if service_status.current_state != CurrentState.SERVICE_STOPPED:
                    scmr_api.control_service(service_handle,
                                             ControlCode.SERVICE_CONTROL_STOP)
                scmr_api.delete_service(service_handle)
                scmr_api.close_service_handle_w(service_handle)

            # copy the executable across and overwrite the existing file
            tree_admin = TreeConnect(session, r"\\%s\ADMIN$"
                                     % session.connection.server_name)
            tree_admin.connect()

            # Copy the paexec payload to the host
            paexec = Open(tree_admin, exe_path)
            paexec.open(ImpersonationLevel.Impersonation,
                        FilePipePrinterAccessMask.FILE_WRITE_DATA,
                        FileAttributes.FILE_ATTRIBUTE_NORMAL,
                        ShareAccess.FILE_SHARE_READ,
                        CreateDisposition.FILE_OVERWRITE_IF,
                        CreateOptions.FILE_NON_DIRECTORY_FILE)
            try:
                for (payload, offset) in exe_payload(65536):
                    paexec.write(payload, offset)
            finally:
                paexec.close(False)

            # now create a branch new service here
            service_handle = scmr_api.create_service_wow64_w(
                scm_handle,
                svc_name,
                svc_name,
                svc_desired_access,
                ServiceType.SERVICE_WIN32_OWN_PROCESS,
                StartType.SERVICE_DEMAND_START,
                ErrorControl.SERVICE_ERROR_NORMAL,
                r'"%SystemRoot%\{0}" -service'.format(exe_path),
                None,
                0,
                None,
                None,
                None)[1]

            # start the new service
            scmr_api.start_service_w(service_handle)
        finally:
            scmr_api.close_service_handle_w(scm_handle)
    finally:
        scmr_api.close()

    # connect to named pipe of the service
    tree = TreeConnect(session, r"\\%s\IPC$" % session.connection.server_name)
    tree.connect()

    settings = PAExecSettingsBuffer()
    settings['username'] = username.encode('utf-16-le')
    settings['password'] = password.encode('utf-16-le')
    settings['executable'] = exe.encode('utf-16-le')
    settings['arguments'] = arguments.encode('utf-16-le')

    input_data_struct = PAExecSettingsMsg()
    input_data_struct['unique_id'] = paexec_id
    input_data_struct['buffer'] = settings
    input_data = input_data_struct.pack()

    cleanup_pipes = []
    try:
        # create pipes and connect to them
        main_name = "%s.exe" % svc_name
        stdout_name = "PaExecOut%s%d" % (current_host, pid)
        stderr_name = "PaExecErr%s%d" % (current_host, pid)
        stdin_name = "PaExecIn%s%d" % (current_host, pid)

        # create the pipes for RemCom
        main_access_mask = FilePipePrinterAccessMask.GENERIC_READ | \
            FilePipePrinterAccessMask.GENERIC_WRITE | \
            FilePipePrinterAccessMask.FILE_APPEND_DATA | \
            FilePipePrinterAccessMask.READ_CONTROL | \
            FilePipePrinterAccessMask.SYNCHRONIZE

        # connect to the main pipe and read the output
        main_pipe = create_pipe(tree, main_name, main_access_mask)
        main_pipe.write(input_data, 0)
        main_out = main_pipe.read(0, 1024, wait=True)
        main_out_resp = PAExecMsg()
        main_out_resp.unpack(main_out)
        main_out_resp.check_resp()

        # send the start process
        start_msg = PAExecMsg()
        start_msg['msg_id'] = PAExecMsgId.MSGID_START_APP
        start_msg['unique_id'] = paexec_id

        start_msg_buffer = PAExecStartBuffer()
        start_msg_buffer['process_id'] = pid
        start_msg_buffer['comp_name'] = current_host.encode('utf-16-le')
        start_msg['buffer'] = start_msg_buffer
        start_msg_b = start_msg.pack()

        main_pipe.write(start_msg_b, 0)

        out_access_mask = FilePipePrinterAccessMask.FILE_READ_DATA | \
            FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
            FilePipePrinterAccessMask.FILE_READ_EA | \
            FilePipePrinterAccessMask.READ_CONTROL | \
            FilePipePrinterAccessMask.SYNCHRONIZE
        ioctl_pipe(tree, stdout_name)
        stdout_pipe = create_pipe(tree, stdout_name, out_access_mask)

        ioctl_pipe(tree, stderr_name)
        stderr_pipe = create_pipe(tree, stderr_name, out_access_mask)

        in_access_mask = FilePipePrinterAccessMask.FILE_WRITE_DATA | \
                         FilePipePrinterAccessMask.FILE_APPEND_DATA | \
                         FilePipePrinterAccessMask.FILE_WRITE_EA | \
                         FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES | \
                         FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
                         FilePipePrinterAccessMask.READ_CONTROL | \
                         FilePipePrinterAccessMask.SYNCHRONIZE
        ioctl_pipe(tree, stdin_name)
        stdin_pipe = create_pipe(tree, stdin_name, in_access_mask)

        stdout = b""
        stderr = b""
        stdout_queue = Queue()
        stderr_queue = Queue()
        stdout_proc = Process(target=read_pipe, args=(stdout_pipe,stdout_queue,))
        stderr_proc = Process(target=read_pipe, args=(stderr_pipe,stderr_queue,))
        stdout_proc.start()
        stderr_proc.start()

        # need to run this after the stdout/stderr calls, wait until the dummy
        # result is sent
        stdout_queue.get()
        stderr_queue.get()
        resp = main_pipe.read(0, 1024, wait=True)

        # process is finished so the stdout jobs should be complete
        stdout_proc.join()
        stderr_proc.join()
        while True:
            try:
                stdout += stdout_queue.get(block=False)
            except Empty:
                break
        while True:
            try:
                stderr += stderr_queue.get(block=False)
            except Empty:
                break

        resp_msg = PAExecMsg()
        resp_msg.unpack(resp)
        resp_msg.check_resp()
        rc = PAExecReturnBuffer()
        rc.unpack(resp_msg['buffer'].get_value())
    finally:
        tree.disconnect()

    # stop and delete the service at the end
    scmr_api = SCMRApi(session)
    scmr_api.open()
    try:
        sc_desired_access = DesiredAccess.SC_MANAGER_CONNECT | \
            DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE
        scm_handle = scmr_api.open_sc_manager_w(server, None, sc_desired_access)
        try:
            svc_desired_access = DesiredAccess.SERVICE_QUERY_STATUS | \
                                 DesiredAccess.SERVICE_STOP | \
                                 DesiredAccess.DELETE

            try:
                service_handle = scmr_api.open_service_w(scm_handle, svc_name,
                                                         svc_desired_access)
            except SCMRException as exc:
                if exc.return_code != 1060:
                    raise exc
            else:
                service_status = scmr_api.query_service_status(service_handle)
                if service_status.current_state != CurrentState.SERVICE_STOPPED:
                    scmr_api.control_service(service_handle,
                                             ControlCode.SERVICE_CONTROL_STOP)
                scmr_api.delete_service(service_handle)
                scmr_api.close_service_handle_w(service_handle)
        finally:
            scmr_api.close_service_handle_w(scm_handle)
    finally:
        scmr_api.close()

    # Delete the executable at the end of the task
    tree_admin = TreeConnect(session, r"\\%s\ADMIN$"
                             % session.connection.server_name)
    tree_admin.connect()

    paexec = Open(tree_admin, exe_path)
    paexec.open(ImpersonationLevel.Impersonation,
                FilePipePrinterAccessMask.FILE_READ_DATA |
                FilePipePrinterAccessMask.DELETE,
                0,
                0,
                CreateDisposition.FILE_OVERWRITE_IF,
                CreateOptions.FILE_NON_DIRECTORY_FILE |
                CreateOptions.FILE_DELETE_ON_CLOSE)
    paexec.close(False)
    tree_admin.disconnect()
finally:
    connection.disconnect()

time.sleep(2)
print("RC: %d" % rc['return_code'].get_value())
print("STDOUT:\n%s" % stdout.decode('utf-8'))
print("STDERR:\n%s" % stderr.decode('utf-8'))
