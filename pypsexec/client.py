import binascii
import os
import socket
import sys
import uuid

from smbprotocol.connection import Connection
from smbprotocol.open import CreateDisposition, CreateOptions, \
    FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel, Open, \
    ShareAccess
from smbprotocol.session import Session
from smbprotocol.tree import TreeConnect

from pypsexec.paexec import PAEXEC_DATA, PAExecMsg, PAExecMsgId, \
    PAExecReturnBuffer, PAExecSettingsBuffer, PAExecSettingsMsg, \
    PAExecStartBuffer, ProcessPriority, get_unique_id
from pypsexec.pipe import InputPipe, OutputPipe
from pypsexec.scmr import Service

if sys.version[0] == '2':
    from Queue import Empty
else:
    from queue import Empty


class Client(object):

    def __init__(self, username, password, server, port=445, encrypt=True):
        self.server = server
        self.port = port
        self.username = username
        self.password = password
        self.pid = os.getpid()
        self.current_host = socket.gethostname()
        self.connection = Connection(uuid.uuid4(), server, port)
        self.session = Session(self.connection, username, password,
                               require_encryption=encrypt)

        self._service_name = "PAExec-%d-%s" % (self.pid, self.current_host)
        self._exe_file = "%s.exe" % self._service_name
        self._stdout_pipe_name = "PaExecOut%s%d"\
                                 % (self.current_host, self.pid)
        self._stderr_pipe_name = "PaExecErr%s%d"\
                                 % (self.current_host, self.pid)
        self._stdin_pipe_name = "PaExecIn%s%d" % (self.current_host, self.pid)
        self._unique_id = get_unique_id(self.pid, self.current_host)
        self._service = Service(self._service_name, self.session)

    def connect(self):
        self.connection.connect()
        self.session.connect()
        self._service.open()

    def disconnect(self):
        self._service.close()
        self.connection.disconnect(True)

    def create_service(self):
        # check if the service exists and delete it
        self._service.refresh()
        if self._service.exists:
            self._service.delete()

        # copy across the PAExec payload to C:\Windows\
        smb_tree = TreeConnect(self.session,
                               r"\\%s\ADMIN$" % self.connection.server_name)
        smb_tree.connect()
        paexec_file = Open(smb_tree, self._exe_file)
        paexec_file.open(ImpersonationLevel.Impersonation,
                         FilePipePrinterAccessMask.FILE_WRITE_DATA,
                         FileAttributes.FILE_ATTRIBUTE_NORMAL,
                         ShareAccess.FILE_SHARE_READ,
                         CreateDisposition.FILE_OVERWRITE_IF,
                         CreateOptions.FILE_NON_DIRECTORY_FILE)
        paexec_file.write(binascii.unhexlify(PAEXEC_DATA), 0)
        paexec_file.close(False)
        smb_tree.disconnect()

        # create the PAExec service and start it
        self._service.open()
        service_path = r'"%SystemRoot%\{0}" -service'.format(self._exe_file)
        self._service.create(self._service_name, service_path)

    def remove_service(self):
        # Stops/removes the PAExec service and removes the executable
        self._service.refresh()
        if self._service.exists:
            self._service.delete()

        # delete the PAExec executable
        smb_tree = TreeConnect(self.session,
                               r"\\%s\ADMIN$" % self.connection.server_name)
        smb_tree.connect()
        paexec_file = Open(smb_tree, self._exe_file)
        paexec_file.open(ImpersonationLevel.Impersonation,
                         FilePipePrinterAccessMask.DELETE,
                         FileAttributes.FILE_ATTRIBUTE_NORMAL,
                         0,
                         CreateDisposition.FILE_OVERWRITE_IF,
                         CreateOptions.FILE_NON_DIRECTORY_FILE |
                         CreateOptions.FILE_DELETE_ON_CLOSE)
        paexec_file.close(False)
        smb_tree.disconnect()

    def run_executable(self, executable, arguments=None, processors=None,
                       async=False, load_profile=True,
                       session_to_interact_with=0, interactive=False,
                       run_elevated=True, run_limited=False, username=None,
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
            not, default is True
        :param run_limited: (Bool) Whether to run as a limited user context,
            admin rights are removed, or not, default is False
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
            rc: (Int) The return code of the process
        """
        # ensure the service is started and running
        self._service.start()

        smb_tree = TreeConnect(self.session,
                               r"\\%s\IPC$" % self.connection.server_name)
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
        main_pipe.write(input_data.pack(), 0)

        settings_resp_raw = main_pipe.read(0, 1024, wait=True)
        settings_resp = PAExecMsg()
        settings_resp.unpack(settings_resp_raw)
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
        main_pipe.write(start_msg.pack(), 0)

        if not interactive and not async:
            # create a pipe for stdout, stderr, and stdin and run in a separate
            # thread
            stdout_pipe = OutputPipe(smb_tree, self._stdout_pipe_name)
            stdout_pipe.start()
            stderr_pipe = OutputPipe(smb_tree, self._stderr_pipe_name)
            stderr_pipe.start()
            stdin_pipe = InputPipe(smb_tree, self._stdin_pipe_name)
            stdin_pipe.start()

            # wait until the stdout and stderr pipes have sent their first
            # response
            stdout_pipe.pipe_buffer.get()
            stderr_pipe.pipe_buffer.get()

            # send any input if there was any
            if stdin:
                stdin_pipe.pipe_buffer.put(stdin)

        # read the final response from the process
        exe_result_raw = main_pipe.read(0, 1024, wait=True)

        if not interactive and not async:
            stdout_pipe.close()
            stderr_pipe.close()
            stdin_pipe.close()
            stdout = self._empty_queue(stdout_pipe.pipe_buffer)
            stderr = self._empty_queue(stderr_pipe.pipe_buffer)
        else:
            stdout = None
            stderr = None

        main_pipe.close()
        smb_tree.disconnect()

        # we know the service has stopped once the process is finished
        self._service.status = "stopped"

        exe_result = PAExecMsg()
        exe_result.unpack(exe_result_raw)
        exe_result.check_resp()
        rc = PAExecReturnBuffer()
        rc.unpack(exe_result['buffer'].get_value())

        return_code = rc['return_code'].get_value()
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
