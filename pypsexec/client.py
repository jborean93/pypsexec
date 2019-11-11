# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import errno
import logging
import os
import socket
import threading

from io import (
    BytesIO,
)

from six import (
    binary_type,
)

from smbclient import (
    delete_session,
    listdir,
    open_file,
    register_session,
    remove,
)

from smbprotocol.change_notify import (
    CompletionFilter,
    FileSystemWatcher,
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
    read_pipe,
    write_pipe,
)

from pypsexec.scmr import (
    EnumServiceState,
    SCMRException,
    ScmrReturnValues,
    Service,
    ServiceType,
)

log = logging.getLogger(__name__)


class Client(object):

    def __init__(self, server, username=None, password=None, port=445, encrypt=True):
        """
        Creates a Client object that can be used to execute processes on a remote host through SMB.

        :param server: The server to connect to.
        :param username: Optional username used for authentication, processes will run under this account unless
            username is specified on `run_executable()`. This can be None if Kerberos auth is being used.
        :param password: The password for username.
        :param port: Override the SMB port used (default: 445).
        :param encrypt: Whether to encrypt the SMB traffic, this should be set to True unless connecting to an older
            host that does not support SMB encryption (default: True).
        """
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
        Removes the PAExec service and executable that was created as part of the create_service function. This does
        not remove any older executables or services from previous runs, use cleanup() instead for that purpose.
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
            if err.errno != errno.ENOENT:
                raise

    def cleanup(self):
        """
        Cleans up any old services or payloads that may have been left behind on a previous failure. This will search
        C:\\Windows for any files starting with PAExec-*.exe and delete them. It will also stop and remove any services
        that start with PAExec-* if they exist.

        Before calling this function, the connect() function must have already been called.
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

    def run_executable(self, executable, arguments=None, processors=None, asynchronous=False, load_profile=True,
                       interactive_session=0, interactive=False, run_elevated=False, run_limited=False, username=None,
                       password=None, use_system_account=False, working_dir=None, show_ui_on_win_logon=False,
                       priority=ProcessPriority.NORMAL_PRIORITY_CLASS, remote_log_path=None, timeout_seconds=0,
                       stdout=None, stderr=None, stdin=None, wow64=False):
        """
        Runs a command over the PAExec/PSExec interface based on the options provided. At a minimum the executable
        argument is required and the rest can stay as the defaults.

        The default configuration for a process (with no changes) is;
            User: The user that authenticated the SMB Session
            Elevation: Highest possible
            Working Dir: %SYSTEM_ROOT%\\System32
            Interactive: False
            Priority: Normal

        :param executable: (String) The executable to be run
        :param arguments: (String) Arguments to run with the executable
        :param processors: (List<Int>) The processors that the process can run on, default is all the processors
        :param asynchronous: (Bool) Whether to run the process and not wait for the output, it will continue to run in
            the background. The stdout and stderr return value will be None and the rc is not reflective of the running
            process
        :param load_profile: (Bool) Whether to load the user profile, default is True
        :param interactive_session: (Int) The session id that an interactive process will run on, use with
            interactive=True to run a process on an existing session
        :param interactive: (Bool) Whether to run on an interative session or not, default is False. The stdout and
            stderr will be None
        :param run_elevated: (Bool) Whether to run as an elevated process or not, default is False (This only applies
            when username is supplied)
        :param run_limited: (Bool) Whether to run as a limited user context, admin rights are removed, or not, default
            is False (This only applied when username is applied)
        :param username: (String) The username to run the process as, if not set then either the SMB Session account is
            used or NT AUTHORITY\\SYSTEM (use_system_account=True) is used
        :param password: (String) The password for the username account
        :param use_system_account: (Bool) Whether to use the NT AUTHORITY\\SYSTEM account isn't of a normal user
        :param working_dir: (String) The working directory that is used when spawning the process
        :param show_ui_on_win_logon: (Bool) Whether to display the UI on the Winlogon secure desktop
            (use_system_account=True only), default is False
        :param priority: (paexec.ProcessPriority) The process priority level, default is NORMAL_PRIORITY_CLASS
        :param remote_log_path: (String) A path on the remote host to output log files for the PAExec service process
            (for debugging purposes)
        :param timeout_seconds: (Int) A timeout that will force the PAExec process to stop once reached, default is 0
            (no timeout)
        :param stdout: An IO stream that can be written to. The process' stdout will be written to this stream as it is
            received. When set to None the stdout is returned as a byte string of this function (default: None).
        :param stderr: An IO stream that can be written to. The process' stderr will be written to this stream as it is
            received. When set to None the stderr is returned as a byte string of this function (default: None).
        :param stdin: A IO stream that can be read. The bytes read from this stream is sent to the process' stdin pipe.
        :param wow64: Set to True to run the executable as a 32-bit process.
        :return: Tuple(stdout, stderr, rc)
            stdout (Bytes) if stdout=None and not interactive/asynchronous, the process' stdou, otherwise None.
            stderr: (Bytes) if stderr=None and not interactive/asynchronous, the process' stderr, otherwise None.
            rc: (Int) The return code of the process (The pid of the async process when async=True)
        """
        if run_elevated and run_limited:
            raise PypsexecException("Both run_elevated and run_limited are set, only 1 of these can be true")
        if stdin is not None and (asynchronous or interactive):
            raise PypsexecException("Cannot send stdin data on an interactive or asynchronous process")

        # While not perfect this at least lets the client know when a new pipe is added to the IPC$ dir. We have no way
        # of setting a notify on a filename so this is the next best effort in case the pipe takes time to come online.
        with open_file(r'\\%s\IPC$' % self.server, mode='rb', buffering=0, file_type='dir') as ipc_dir:
            pipe_watcher = FileSystemWatcher(ipc_dir.fd)
            pipe_watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)

            log.debug("Making sure PAExec service is running")
            try:
                self._service.start(strict=True)
            except SCMRException as exc:
                if exc.return_code == ScmrReturnValues.ERROR_SERVICE_ALREADY_RUNNING:
                    # The service is already running so the watcher won't fire, just cancel it.
                    pipe_watcher.cancel()
                else:
                    raise
            else:
                # The service was started, wait until the pipe is online
                pipe_watcher.wait()

        # write the settings to the main PAExec pipe
        main_pipe_path = r"\\%s\IPC$\%s" % (self.server, self._exe_file)
        log.info("Connecting to PAExec service main pipe at '%s'" % main_pipe_path)
        with open_file(main_pipe_path, mode='wb+', buffering=0, file_type='pipe') as main_pipe:
            self._send_paexec_settings(main_pipe,
                                       processors=processors if processors else [],
                                       asynchronous=asynchronous,
                                       dont_load_profile=not load_profile,
                                       interactive_session=interactive_session,
                                       interactive=interactive,
                                       run_elevated=run_elevated,
                                       run_limited=run_limited,
                                       username=username,
                                       password=password,
                                       use_system_account=use_system_account,
                                       working_dir=working_dir,
                                       show_ui_on_win_logon=show_ui_on_win_logon,
                                       priority=priority,
                                       executable=executable,
                                       arguments=arguments,
                                       remote_log_path=remote_log_path,
                                       timeout_seconds=timeout_seconds,
                                       disable_file_redirection=not wow64)
            self._start_paexec_process(main_pipe)

            pipe_threads = []
            if not interactive and not asynchronous:
                # Create a pipe for stdout, stderr, and stdin and run in a separate thread.
                log.info("Connecting to remote pipes to retrieve output")

                smb_tree = main_pipe.fd.tree_connect

                stdout_buffer = stdout or BytesIO()
                stderr_buffer = stderr or BytesIO()

                stdin_buffer = stdin or BytesIO()
                if isinstance(stdin_buffer, binary_type):
                    # Backwards compat and easy way to just pass in stdin as a bytes string.
                    stdin_buffer = BytesIO(stdin_buffer)

                pipe_threads.append(self._listen_named_pipe(smb_tree, self._stdout_pipe_name, stdout_buffer))
                pipe_threads.append(self._listen_named_pipe(smb_tree, self._stderr_pipe_name, stderr_buffer))
                pipe_threads.append(self._listen_named_pipe(smb_tree, self._stdin_pipe_name, stdin_buffer, read=False))

            # read the final response from the process
            log.info("Waiting for PAExec process to finish")
            exe_result_raw = main_pipe.read(1024)

            b_stdout = None
            b_stderr = None
            if not interactive and not asynchronous:
                if stdout is None:
                    b_stdout = stdout_buffer.getvalue()
                if stderr is None:
                    b_stderr = stderr_buffer.getvalue()

            log.info("Closing main PAExec pipe")  # Done when exiting the 'with main_pipe' indent.

        return_code = self._get_process_return_code(exe_result_raw)
        log.info("Process finished with exit code: %d" % return_code)
        return b_stdout, b_stderr, return_code

    def _send_paexec_settings(self, pipe, **kwargs):
        settings = PAExecSettingsBuffer()
        for k, v in kwargs.items():
            settings[k] = v

        input_data = PAExecSettingsMsg()
        input_data['unique_id'] = self._unique_id
        input_data['buffer'] = settings

        log.info("Writing PAExecSettingsMsg to the main PAExec pipe")
        log.info(str(input_data))
        pipe.write(input_data.pack())

        log.info("Reading PAExecMsg from the PAExec pipe")
        settings_resp_raw = pipe.read(1024)
        settings_resp = PAExecMsg()
        settings_resp.unpack(settings_resp_raw)
        log.debug(str(settings_resp))
        settings_resp.check_resp()

    def _start_paexec_process(self, pipe):
        start_msg = PAExecMsg()
        start_msg['msg_id'] = PAExecMsgId.MSGID_START_APP
        start_msg['unique_id'] = self._unique_id

        start_buffer = PAExecStartBuffer()
        start_buffer['process_id'] = self.pid
        start_buffer['comp_name'] = self.current_host
        start_msg['buffer'] = start_buffer

        log.info("Writing PAExecMsg with PAExecStartBuffer to start the remote process")
        log.debug(str(start_msg))
        pipe.write(start_msg.pack())

    def _listen_named_pipe(self, ipc_tree, name, pipe_buffer, read=True):
        target = read_pipe if read else write_pipe
        thread_name = "%s-%s" % ("output" if read else "input", name)
        t_listener = threading.Thread(target=target, args=(ipc_tree, name, pipe_buffer), name=thread_name)
        t_listener.daemon = True
        t_listener.start()
        return t_listener

    def _get_process_return_code(self, b_data):
        log.info("Unpacking PAExecMsg data from process result")
        exe_result = PAExecMsg()
        exe_result.unpack(b_data)
        log.debug(str(exe_result))
        exe_result.check_resp()
        log.debug("Unpacking PAExecReturnBuffer from main PAExecMsg")
        rc = PAExecReturnBuffer()
        rc.unpack(exe_result['buffer'].get_value())
        log.debug(str(rc))
        return rc['return_code'].get_value()
