# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import errno
import logging
import os
import socket
import time

from smbclient import (
    delete_session,
    listdir,
    open_file,
    register_session,
    remove,
)

from smbprotocol.connection import (
    NtStatus,
)

from smbprotocol.exceptions import (
    SMBResponseException,
)

from smbprotocol.open import (
    FilePipePrinterAccessMask,
)

from smbprotocol.tree import (
    TreeConnect,
)

from pypsexec.exceptions import (
    PypsexecException,
)

from pypsexec.paexec import (
    PAExecMsg,
    PAExecMsgId,
    PAExecReturnBuffer,
    PAExecSettingsBuffer,
    PAExecSettingsMsg,
    PAExecStartBuffer,
    ProcessPriority,
    get_unique_id,
    paexec_out_stream,
)

from pypsexec.pipe import (
    InputPipe,
    OutputPipeBytes,
    open_pipe,
)

from pypsexec.scmr import (
    EnumServiceState,
    Service,
    ServiceType,
)

log = logging.getLogger(__name__)


class Client(object):

    def __init__(self, server, username=None, password=None, port=445,
                 encrypt=True):
        self.server = server
        self.port = port
        self.pid = os.getpid()
        self.current_host = socket.gethostname()
        self.username = username
        self.password = password
        self.encrypt = encrypt

        self.service_name = "PAExec-%d-%s" % (self.pid, self.current_host)
        log.info("Creating PyPsexec Client with unique name: %s" % self.service_name)
        self._exe_file = "%s.exe" % self.service_name
        self._stdout_pipe_name = "PaExecOut%s%d" % (self.current_host, self.pid)
        self._stderr_pipe_name = "PaExecErr%s%d" % (self.current_host, self.pid)
        self._stdin_pipe_name = "PaExecIn%s%d" % (self.current_host, self.pid)
        self._unique_id = get_unique_id(self.pid, self.current_host)
        log.info("Generated unique ID for PyPsexec Client: %d" % self._unique_id)
        self._service = Service(self.service_name, self.server)

    def __enter__(self):
        self.connect()
        self.create_service()
        return self

    def __exit__(self, exc_type, exc_value, exc_tb):
        try:
            self.remove_service()
        finally:
            self.disconnect()

    def connect(self, timeout=60):
        log.info("Setting up SMB Connection to %s:%d" % (self.server, self.port))
        register_session(self.server, username=self.username, password=self.password, port=self.port,
                         encrypt=self.encrypt, connection_timeout=timeout)

        log.info("Opening handle to SCMR and PAExec service")
        self._service.open()

    def disconnect(self):
        log.info("Closing handle of PAExec service and SCMR")
        self._service.close()

        log.info("Closing SMB Connection")
        delete_session(self.server, port=self.port)

    def create_service(self):
        # check if the service exists and delete it
        log.debug("Ensuring service is deleted before starting")
        self._service.delete()

        # copy across the PAExec payload to C:\Windows\
        paexec_path = r"\\%s\ADMIN$\%s" % (self.server, self._exe_file)
        log.debug("Opening PAExec at '%s' with write access" % paexec_path)
        with open_file(paexec_path, mode='wb', buffering=0) as paexec_fd:
            log.debug("Writing PAExec executable to remote server")
            for b_data in paexec_out_stream(paexec_fd.fd.connection.max_write_size):
                paexec_fd.write(b_data)

        # create the PAExec service
        service_path = r'"%SystemRoot%\{0}" -service'.format(self._exe_file)
        log.info("Creating PAExec service %s" % self.service_name)
        self._service.create(service_path)

    def remove_service(self):
        """
        Removes the PAExec service and executable that was created as part of
        the create_service function. This does not remove any older executables
        or services from previous runs, use cleanup() instead for that purpose.
        """
        # Stops/remove the PAExec service and removes the executable
        log.debug("Deleting PAExec service at the end of the process")
        self._service.delete()

        # delete the PAExec executable
        paexec_path = r"\\%s\ADMIN$\%s" % (self.server, self._exe_file)
        log.info("Deleting PAExec file at '%s'" % paexec_path)
        try:
            remove(paexec_path)
        except OSError as err:
            if err != errno.ENOENT:
                raise

    def cleanup(self):
        """
        Cleans up any old services or payloads that may have been left behind
        on a previous failure. This will search C:\\Windows for any files
        starting with PAExec-*.exe and delete them. It will also stop and
        remove any services that start with PAExec-* if they exist.

        Before calling this function, the connect() function must have already
        been called.
        """
        scmr = self._service._scmr
        services = scmr.enum_services_status_w(
            self._service._scmr_handle,
            ServiceType.SERVICE_WIN32_OWN_PROCESS,
            EnumServiceState.SERVICE_STATE_ALL)
        for service in services:
            if service['service_name'].lower().startswith("paexec"):
                svc = Service(service['service_name'], self.server)
                svc.open()
                svc.delete()

        admin_share = r"\\%s\ADMIN$" % self.server
        for file_name in listdir(admin_share, "PAExec-*.exe"):
            remove(r"%s\%s" % (admin_share, file_name))

    def run_executable(self, executable, arguments=None, processors=None,
                       asynchronous=False, load_profile=True,
                       interactive_session=0, interactive=False,
                       run_elevated=False, run_limited=False, username=None,
                       password=None, use_system_account=False,
                       working_dir=None, show_ui_on_win_logon=False,
                       priority=ProcessPriority.NORMAL_PRIORITY_CLASS,
                       remote_log_path=None, timeout_seconds=0,
                       stdout=OutputPipeBytes, stderr=OutputPipeBytes,
                       stdin=None, wow64=False):
        """
        Runs a command over the PAExec/PSExec interface based on the options
        provided. At a minimum the executable argument is required and the
        rest can stay as the defaults.

        The default configuration for a process (with no changes) is;
            User: The user that authenticated the SMB Session
            Elevation: Highest possible
            Working Dir: %SYSTEM_ROOT%\\System32
            Interactive: False
            Priority: Normal

        :param executable: (String) The executable to be run
        :param arguments: (String) Arguments to run with the executable
        :param processors: (List<Int>) The processors that the process can run
            on, default is all the processors
        :param asynchronous: (Bool) Whether to run the process and not wait for
            the output, it will continue to run in the background. The stdout
            and stderr return value will be None and the rc is not reflective
            of the running process
        :param load_profile: (Bool) Whether to load the user profile, default
            is True
        :param interactive_session: (Int) The session id that an
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
            NT AUTHORITY\\SYSTEM (use_system_account=True) is used
        :param password: (String) The password for the username account
        :param use_system_account: (Bool) Whether to use the
            NT AUTHORITY\\SYSTEM account isn't of a normal user
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
        :param stdout: (pipe.OutputPipe) An class that implements of
            pipe.OutputPipe that handles the Named Pipe stdout output. The
            default is pipe.OutputPipeBytes which returns a byte string of the
            stdout
        :param stderr: (pipe.OutputPipe) An class that implements of
            pipe.OutputPipe that handles the Named Pipe stderr output. The
            default is pipe.OutputPipeBytes which returns a byte string of the
            stderr
        :param stdin: Either a byte string of generator that yields multiple
            byte strings to send over the stdin pipe.
        :param wow64: Set to True to run the executable as a 32-bit process.
        :return: Tuple(stdout, stderr, rc)
            stdout: (Bytes) The stdout.get_bytes() return result
            stderr: (Bytes) The stderr.get_bytes() return result
            rc: (Int) The return code of the process (The pid of the async
                process when async=True)
        """
        if run_elevated and run_limited:
            raise PypsexecException("Both run_elevated and run_limited are "
                                    "set, only 1 of these can be true")
        if stdin is not None and (asynchronous or interactive):
            raise PypsexecException("Cannot send stdin data on an interactive "
                                    "or asynchronous process")

        log.debug("Making sure PAExec service is running")
        self._service.start()

        settings = PAExecSettingsBuffer()
        settings['processors'] = processors if processors else []
        settings['asynchronous'] = asynchronous
        settings['dont_load_profile'] = not load_profile
        settings['interactive_session'] = interactive_session
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
        settings['disable_file_redirection'] = not wow64

        input_data = PAExecSettingsMsg()
        input_data['unique_id'] = self._unique_id
        input_data['buffer'] = settings

        # write the settings to the main PAExec pipe
        main_pipe_path = r"\\%s\IPC$\%s" % (self.server, self._exe_file)
        main_pipe = None
        for i in range(0, 3):
            try:
                main_pipe = open_file(main_pipe_path, mode='wb+', buffering=0,
                                      file_type='pipe')
            except OSError as err:
                if err != errno.ENOENT:
                    raise
                elif i == 2:
                    raise PypsexecException("Failed to open main PAExec pipe "
                                            "%s, no more attempts remaining"
                                            % self._exe_file)
                log.warning("Main pipe %s does not exist yet on attempt %d. "
                            "Trying again in 5 seconds"
                            % (self._exe_file, i + 1))
                time.sleep(5)
            else:
                break

        with main_pipe:
            log.info("Writing PAExecSettingsMsg to the main PAExec pipe")
            log.info(str(input_data))
            main_pipe.write(input_data.pack())

            log.info("Reading PAExecMsg from the PAExec pipe")
            settings_resp_raw = main_pipe.read(1024)
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
            main_pipe.write(start_msg.pack())

            if not interactive and not asynchronous:
                # create a pipe for stdout, stderr, and stdin and run in a separate
                # thread
                log.info("Connecting to remote pipes to retrieve output")
                stdout_pipe = stdout(smb_tree, self._stdout_pipe_name)
                stdout_pipe.start()
                stderr_pipe = stderr(smb_tree, self._stderr_pipe_name)
                stderr_pipe.start()
                stdin_pipe = InputPipe(smb_tree, self._stdin_pipe_name)

            # wait until the stdout and stderr pipes have sent their first
            # response
            log.debug("Waiting for stdout pipe to send first request")
            while not stdout_pipe.sent_first:
                pass
            log.debug("Waiting for stderr pipe to send first request")
            while not stderr_pipe.sent_first:
                pass

            # send any input if there was any
            try:
                if stdin and isinstance(stdin, bytes):
                    log.info("Sending stdin bytes over stdin pipe: %s"
                             % self._stdin_pipe_name)
                    stdin_pipe.write(stdin)
                elif stdin:
                    log.info("Sending stdin generator bytes over stdin pipe: "
                             "%s" % self._stdin_pipe_name)
                    for stdin_data in stdin():
                        stdin_pipe.write(stdin_data)
            except SMBResponseException as exc:
                # if it fails with a STATUS_PIPE_BROKEN exception, continue as
                # the actual error will be in the response (process failed)
                if exc.status != NtStatus.STATUS_PIPE_BROKEN:
                    raise exc
                log.warning("Failed to send data through stdin: %s" % str(exc))

        # read the final response from the process
        log.info("Reading result of PAExec process")
        exe_result_raw = main_pipe.read(0, 1024)
        log.info("Results read of PAExec process")

        if not interactive and not asynchronous:
            log.info("Closing PAExec std* pipes")
            stdout_pipe.close()
            stderr_pipe.close()
            stdin_pipe.close()
            log.info("Gettings stdout and stderr from pipe buffer queue")
            stdout_out = stdout_pipe.get_output()
            stderr_bytes = stderr_pipe.get_output()
        else:
            stdout_out = None
            stderr_bytes = None

        log.info("Closing main PAExec pipe")
        main_pipe.close()
        log.info("Disconnecting from SMB Tree %s" % smb_tree.share_name)
        smb_tree.disconnect()

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
        log.debug("RC: %d" % return_code)
        return stdout_out, stderr_bytes, return_code

    def _encode_string(self, string):
        return string.encode('utf-16-le') if string else None
