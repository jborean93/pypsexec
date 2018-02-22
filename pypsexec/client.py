import logging
import os
import socket
import sys
import uuid

from smbprotocol.connection import Connection, NtStatus
from smbprotocol.exceptions import SMBResponseException
from smbprotocol.open import CreateDisposition, CreateOptions, \
    DirectoryAccessMask, FileAttributes, FileInformationClass, \
    FilePipePrinterAccessMask, ImpersonationLevel, Open, ShareAccess
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

from pypsexec.exceptions import PypsexecException
from pypsexec.paexec import PAExecMsg, PAExecMsgId, PAExecReturnBuffer, \
    PAExecSettingsBuffer, PAExecSettingsMsg, PAExecStartBuffer, \
    ProcessPriority, get_unique_id, paexec_out_stream
from pypsexec.pipe import InputPipe, OutputPipe
from pypsexec.scmr import DesiredAccess, EnumServiceState, SCMRApi, Service, \
    ServiceType

if sys.version[0] == '2':
    from Queue import Empty
else:
    from queue import Empty

log = logging.getLogger(__name__)


class Client(object):

    def __init__(self, server, username=None, password=None, port=445,
                 encrypt=True):
        self.server = server
        self.port = port
        self.pid = os.getpid()
        self.current_host = socket.gethostname()
        self.connection = Connection(uuid.uuid4(), server, port)
        self.session = Session(self.connection, username, password,
                               require_encryption=encrypt)

        self.service_name = "PAExec-%d-%s" % (self.pid, self.current_host)
        log.info("Creating PyPsexec Client with unique name: %s"
                 % self.service_name)
        self._exe_file = "%s.exe" % self.service_name
        self._stdout_pipe_name = "PaExecOut%s%d"\
                                 % (self.current_host, self.pid)
        self._stderr_pipe_name = "PaExecErr%s%d"\
                                 % (self.current_host, self.pid)
        self._stdin_pipe_name = "PaExecIn%s%d" % (self.current_host, self.pid)
        self._unique_id = get_unique_id(self.pid, self.current_host)
        log.info("Generated unique ID for PyPsexec Client: %d"
                 % self._unique_id)
        self._service = Service(self.service_name, self.session)

    def connect(self):
        log.info("Setting up SMB Connection to %s:%d"
                 % (self.server, self.port))
        self.connection.connect()
        log.info("Authenticating SMB Session")
        self.session.connect()
        log.info("Opening handle to SCMR and PAExec service")
        self._service.open()

    def disconnect(self):
        log.info("Closing handle of PAExec service and SCMR")
        self._service.close()
        log.info("Closing SMB Connection")
        self.connection.disconnect(True)

    def create_service(self):
        # check if the service exists and delete it
        log.debug("Refreshing service details")
        self._service.refresh()
        if self._service.exists:
            log.info("An existing PAExec service with the name %s exists, "
                     "deleting the service" % self.service_name)
            self._service.delete()

        # copy across the PAExec payload to C:\Windows\
        smb_tree = TreeConnect(self.session,
                               r"\\%s\ADMIN$" % self.connection.server_name)
        log.info("Connecting to SMB Tree %s" % smb_tree.share_name)
        smb_tree.connect()
        paexec_file = Open(smb_tree, self._exe_file)
        log.debug("Creating open to PAExec file")
        paexec_file.open(ImpersonationLevel.Impersonation,
                         FilePipePrinterAccessMask.FILE_WRITE_DATA,
                         FileAttributes.FILE_ATTRIBUTE_NORMAL,
                         ShareAccess.FILE_SHARE_READ,
                         CreateDisposition.FILE_OVERWRITE_IF,
                         CreateOptions.FILE_NON_DIRECTORY_FILE)
        log.info("Creating PAExec executable at %s\\%s"
                 % (smb_tree.share_name, self._exe_file))
        for (data, o) in paexec_out_stream(self.connection.max_write_size):
            paexec_file.write(data, o)
        log.debug("Closing open to PAExec file")
        paexec_file.close(False)
        log.info("Disconnecting from SMB Tree %s" % smb_tree.share_name)
        smb_tree.disconnect()

        # create the PAExec service and start it
        log.debug("Making sure we have an open Service handle")
        self._service.open()
        service_path = r'"%SystemRoot%\{0}" -service'.format(self._exe_file)
        log.info("Creating PAExec service %s" % self.service_name)
        self._service.create(service_path)

    def remove_service(self):
        """
        Removes the PAExec service and executable that was created as part of
        the create_service function. This does not remove any older executables
        or services from previous runs, use cleanup() instead for that purpose.
        """
        # Stops/removes the PAExec service and removes the executable
        log.debug("Refreshing service details")
        self._service.refresh()
        if self._service.exists:
            log.info("PAExec service exists, deleting")
            self._service.delete()

        # delete the PAExec executable
        smb_tree = TreeConnect(self.session,
                               r"\\%s\ADMIN$" % self.connection.server_name)
        log.info("Connecting to SMB Tree %s" % smb_tree.share_name)
        smb_tree.connect()
        paexec_file = Open(smb_tree, self._exe_file)
        log.info("Creating open to PAExec file with delete on close flags")
        paexec_file.open(ImpersonationLevel.Impersonation,
                         FilePipePrinterAccessMask.DELETE,
                         FileAttributes.FILE_ATTRIBUTE_NORMAL,
                         0,
                         CreateDisposition.FILE_OVERWRITE_IF,
                         CreateOptions.FILE_NON_DIRECTORY_FILE |
                         CreateOptions.FILE_DELETE_ON_CLOSE)
        log.debug("Closing PAExec open")
        paexec_file.close(False)
        log.info("Disconnecting from SMB Tree %s" % smb_tree.share_name)
        smb_tree.disconnect()

    def cleanup(self):
        """
        Cleans up any old services or payloads that may have been left behind
        on a previous failure. This will search C:\Windows for any files
        starting with PAExec-*.exe and delete them. It will also stop and
        remove any services that start with PAExec-* if they exist.

        Before calling this function, the connect() function must have already
        been called.
        """
        scmr = SCMRApi(self.session)
        scmr.open()
        sc_desired_access = DesiredAccess.SC_MANAGER_CONNECT | \
            DesiredAccess.SC_MANAGER_CREATE_SERVICE | \
            DesiredAccess.SC_MANAGER_ENUMERATE_SERVICE
        scmr_handle = scmr.open_sc_manager_w(self.connection.server_name,
                                             None, sc_desired_access)
        try:
            services = scmr.enum_services_status_w(scmr_handle,
                                                   ServiceType.
                                                   SERVICE_WIN32_OWN_PROCESS,
                                                   EnumServiceState.
                                                   SERVICE_STATE_ALL)
            for service in services:
                if service['service_name'].lower().startswith("paexec"):
                    svc = Service(service['service_name'], self.session)
                    svc.open()
                    svc.delete()
                    svc.close()
        finally:
            scmr.close_service_handle_w(scmr_handle)
            scmr.close()

        smb_tree = TreeConnect(self.session,
                               r"\\%s\ADMIN$" % self.connection.server_name)
        smb_tree.connect()

        share = Open(smb_tree, "")
        share.open(ImpersonationLevel.Impersonation,
                   DirectoryAccessMask.FILE_READ_ATTRIBUTES |
                   DirectoryAccessMask.SYNCHRONIZE |
                   DirectoryAccessMask.FILE_LIST_DIRECTORY,
                   FileAttributes.FILE_ATTRIBUTE_DIRECTORY,
                   ShareAccess.FILE_SHARE_READ | ShareAccess.FILE_SHARE_WRITE |
                   ShareAccess.FILE_SHARE_DELETE,
                   CreateDisposition.FILE_OPEN,
                   CreateOptions.FILE_DIRECTORY_FILE)
        try:
            files = share.query_directory("PAExec-*.exe",
                                          FileInformationClass.
                                          FILE_NAMES_INFORMATION)
        except SMBResponseException as exc:
            if exc.status != NtStatus.STATUS_NO_SUCH_FILE:
                raise exc
            files = []

        for file in files:
            file_name = file['file_name'].get_value().decode('utf-16-le')
            file_open = Open(smb_tree, file_name)
            file_open.open(ImpersonationLevel.Impersonation,
                           FilePipePrinterAccessMask.DELETE,
                           FileAttributes.FILE_ATTRIBUTE_NORMAL,
                           0,
                           CreateDisposition.FILE_OPEN,
                           CreateOptions.FILE_NON_DIRECTORY_FILE |
                           CreateOptions.FILE_DELETE_ON_CLOSE)
            file_open.close(get_attributes=False)

    def run_executable(self, executable, arguments=None, processors=None,
                       async=False, load_profile=True,
                       session_to_interact_with=0, interactive=False,
                       run_elevated=False, run_limited=False, username=None,
                       password=None, use_system_account=False,
                       working_dir=None, show_ui_on_win_logon=False,
                       priority=ProcessPriority.NORMAL_PRIORITY_CLASS,
                       remote_log_path=None, timeout_seconds=0, stdin=None):
        """
        Runs a command over the PAExec/PSExec interface based on the options
        provided. At a minimum the executable argument is required and the
        rest can stay as the defaults.

        The default configuration for a process (with no changes) is;
            User: The user that authenticated the SMB Session
            Elevation: Highest possible
            Working Dir: %SYSTEM_ROOT%\System32
            Interactive: False
            Priority: Normal

        :param executable: (String) The executable to be run
        :param arguments: (String) Arguments to run with the executable
        :param processors: (List<Int>) The processors that the process can run
            on, default is all the processors
        :param async: (Bool) Whether to run the process and not wait for the
            output, it will continue to run in the background. The stdout and
            stderr return value will be None and the rc is not reflective of
            the running process
        :param load_profile: (Bool) Whether to load the user profile, default
            is True
        :param session_to_interact_with: (Int) The session id that an
            interactive process will run on, use with interactive=True to
            run a process on an existing session
        :param interactive: (Bool) Whether to run on an interative session or
            not, default is False. The stdout and stderr will be None
        :param run_elevated: (Bool) Whether to run as an elevated process or
            not, default is False (This only applies when username is supplied)
        :param run_limited: (Bool) Whether to run as a limited user context,
            admin rights are removed, or not, default is False (This only
            applied when username is applied)
        :param username: (String) The username to run the process as, if not
            set then either the SMB Session account is used or
            NT AUTHORITY\SYSTEM (use_system_account=True) is used
        :param password: (String) The password for the username account
        :param use_system_account: (Bool) Whether to use the
            NT AUTHORITY\SYSTEM account isn't of a normal user
        :param working_dir: (String) The working directory that is used when
            spawning the process
        :param show_ui_on_win_logon: (Bool) Whether to display the UI on the
            Winlogon secure desktop (use_system_account=True only), default is
            False
        :param priority: (paexec.ProcessPriority) The process priority level,
            default is NORMAL_PRIORITY_CLASS
        :param remote_log_path: (String) A path on the remote host to output
            log files for the PAExec service process (for debugging purposes)
        :param timeout_seconds: (Int) A timeout that will force the PAExec
            process to stop once reached, default is 0 (no timeout)
        :param stdin: (Bytes) A byte string to send over the stdin pipe once
            the process has been spawned. This must be a bytes string and not
            a normal Python string
        :return: Tuple(stdout, stderr, rc)
            stdout: (Bytes) The stdout as a byte string from the process
            stderr: (Bytes) The stderr as a byte string from the process
            rc: (Int) The return code of the process (The pid of the async
                process when async=True)
        """
        if run_elevated and run_limited:
            raise PypsexecException("Both run_elevated and run_limited are "
                                    "set, only 1 of these can be true")

        # ensure the service is started and running
        log.debug("Making sure PAExec service is running")
        self._service.start()

        smb_tree = TreeConnect(self.session,
                               r"\\%s\IPC$" % self.connection.server_name)
        log.info("Connecting to SMB Tree %s" % smb_tree.share_name)
        smb_tree.connect()

        settings = PAExecSettingsBuffer()
        settings['processors'] = processors if processors else []
        settings['async'] = async
        settings['dont_load_profile'] = not load_profile
        settings['session_to_interact_with'] = session_to_interact_with
        settings['interactive'] = interactive
        settings['run_elevated'] = run_elevated
        settings['run_limited'] = run_limited
        settings['username'] = self._encode_string(username)
        settings['password'] = self._encode_string(password)
        settings['use_system_account'] = use_system_account
        settings['working_dir'] = self._encode_string(working_dir)
        settings['show_ui_on_win_logon'] = show_ui_on_win_logon
        settings['priority'] = priority
        settings['executable'] = self._encode_string(executable)
        settings['arguments'] = self._encode_string(arguments)
        settings['remote_log_path'] = self._encode_string(remote_log_path)
        settings['timeout_seconds'] = timeout_seconds

        input_data = PAExecSettingsMsg()
        input_data['unique_id'] = self._unique_id
        input_data['buffer'] = settings

        # write the settings to the main PAExec pipe
        main_pipe = Open(smb_tree, self._exe_file)
        log.info("Creating open to main PAExec pipe: %s" % self._exe_file)
        main_pipe.open(
            ImpersonationLevel.Impersonation,
            FilePipePrinterAccessMask.GENERIC_READ |
            FilePipePrinterAccessMask.GENERIC_WRITE |
            FilePipePrinterAccessMask.FILE_APPEND_DATA |
            FilePipePrinterAccessMask.READ_CONTROL |
            FilePipePrinterAccessMask.SYNCHRONIZE,
            FileAttributes.FILE_ATTRIBUTE_NORMAL,
            0,
            CreateDisposition.FILE_OPEN,
            CreateOptions.FILE_NON_DIRECTORY_FILE |
            CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT
        )
        log.info("Writing PAExecSettingsMsg to the main PAExec pipe")
        log.info(str(input_data))
        main_pipe.write(input_data.pack(), 0)

        log.info("Reading PAExecMsg from the PAExec pipe")
        settings_resp_raw = main_pipe.read(0, 1024)
        settings_resp = PAExecMsg()
        settings_resp.unpack(settings_resp_raw)
        log.debug(str(settings_resp))
        settings_resp.check_resp()

        # start the process now
        start_msg = PAExecMsg()
        start_msg['msg_id'] = PAExecMsgId.MSGID_START_APP
        start_msg['unique_id'] = self._unique_id
        start_msg['buffer'] = PAExecStartBuffer()
        start_buffer = PAExecStartBuffer()
        start_buffer['process_id'] = self.pid
        start_buffer['comp_name'] = self.current_host.encode('utf-16-le')
        start_msg['buffer'] = start_buffer

        log.info("Writing PAExecMsg with PAExecStartBuffer to start the "
                 "remote process")
        log.debug(str(start_msg))
        main_pipe.write(start_msg.pack(), 0)

        if not interactive and not async:
            # create a pipe for stdout, stderr, and stdin and run in a separate
            # thread
            log.info("Connecting to remote pipes to retrieve output")
            stdout_pipe = OutputPipe(smb_tree, self._stdout_pipe_name)
            stdout_pipe.start()
            stderr_pipe = OutputPipe(smb_tree, self._stderr_pipe_name)
            stderr_pipe.start()
            stdin_pipe = InputPipe(smb_tree, self._stdin_pipe_name)
            stdin_pipe.start()

            # wait until the stdout and stderr pipes have sent their first
            # response
            log.debug("Waiting for stdout pipe to send first request")
            stdout_pipe.pipe_buffer.get()
            log.debug("Waiting for stderr pipe to send first request")
            stderr_pipe.pipe_buffer.get()

            # send any input if there was any
            if stdin:
                log.info("Sending stdin bytes over stdin pipe: %s"
                         % self._stdin_pipe_name)
                stdin_pipe.pipe_buffer.put(stdin)

        # read the final response from the process
        log.info("Reading result of PAExec process")
        exe_result_raw = main_pipe.read(0, 1024)
        log.info("Results read of PAExec process")

        if not interactive and not async:
            log.info("Closing PAExec std* pipes")
            stdout_pipe.close()
            stderr_pipe.close()
            stdin_pipe.close()
            log.info("Gettings stdout and stderr from pipe buffer queue")
            stdout = self._empty_queue(stdout_pipe.pipe_buffer)
            stderr = self._empty_queue(stderr_pipe.pipe_buffer)
        else:
            stdout = None
            stderr = None

        log.info("Closing main PAExec pipe")
        main_pipe.close()
        log.info("Disconnecting from SMB Tree %s" % smb_tree.share_name)
        smb_tree.disconnect()

        # we know the service has stopped once the process is finished
        self._service.status = "stopped"

        log.info("Unpacking PAExecMsg data from process result")
        exe_result = PAExecMsg()
        exe_result.unpack(exe_result_raw)
        log.debug(str(exe_result))
        exe_result.check_resp()
        log.debug("Unpacking PAExecReturnBuffer from main PAExecMsg")
        rc = PAExecReturnBuffer()
        rc.unpack(exe_result['buffer'].get_value())
        log.debug(str(rc))

        return_code = rc['return_code'].get_value()
        log.info("Process finished with exit code: %d" % return_code)
        log.debug("STDOUT: %s" % stdout)
        log.debug("STDERR: %s" % stderr)
        log.debug("RC: %d" % return_code)
        return stdout, stderr, return_code

    def _encode_string(self, string):
        return string.encode('utf-16-le') if string else None

    def _empty_queue(self, queue):
        data = b""
        while True:
            try:
                data += queue.get(block=False)
            except Empty:
                break

        return data
