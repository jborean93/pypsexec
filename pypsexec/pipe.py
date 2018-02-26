import binascii
import logging
import os
import sys
import threading
import warnings

from abc import ABCMeta, abstractmethod
from six import with_metaclass
from smbprotocol.connection import NtStatus
from smbprotocol.exceptions import SMBResponseException
from smbprotocol.ioctl import CtlCode, IOCTLFlags, SMB2IOCTLRequest
from smbprotocol.open import CreateDisposition, CreateOptions, \
    FileAttributes, FilePipePrinterAccessMask, ImpersonationLevel, Open
from smbprotocol.structure import BoolField, BytesField, IntField, Structure

try:
    from collections import OrderedDict
except ImportError:  # pragma: no cover
    from ordereddict import OrderedDict

if sys.version[0] == '2':
    from Queue import Queue
else:
    from queue import Queue

log = logging.getLogger(__name__)


class TheadCloseTimeoutWarning(Warning):
    pass


def open_pipe(tree, name, access_mask, fsctl_wait=False):
    """
    Opened the requested pipe with the access mask specified. Will attempt
    to connect 3 times before failing in case the pipe's don't exist at the
    time.

    :param tree: The SMB TreeConnect of IPC$ to connect to
    :param name: The name of the pipe to connect to
    :param access_mask: The access mask to apply to the Open
    :param fsctl_wait: Runs the FSCTL_PIPE_WAIT command over an
        SMB2IOCTLRequest
    :return: A connected Open() object of the pipe
    """
    log.info("Creating SMB Open for pipe: %s" % name)
    pipe = Open(tree, name)

    if fsctl_wait:
        wait_pipe = SMB2IOCTLRequest()
        wait_pipe['ctl_code'] = CtlCode.FSCTL_PIPE_WAIT
        wait_pipe['file_id'] = b"\xff" * 16
        wait_pipe['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

        fsctl_data = FSCTLPipeWait()
        fsctl_data['name'] = name.encode('utf-16-le')
        wait_pipe['buffer'] = fsctl_data

        log.info("Sending FSCTL_PIPE_WAIT for pipe %s" % name)
        log.debug(str(fsctl_data))
        request = tree.session.connection.send(
            wait_pipe,
            sid=tree.session.session_id,
            tid=tree.tree_connect_id
        )

        log.info("Receiving FSCTL_PIPE_WAIT response for pipe: %s"
                 % name)
        tree.session.connection.receive(request)

    pipe.create(ImpersonationLevel.Impersonation,
                access_mask,
                FileAttributes.FILE_ATTRIBUTE_NORMAL,
                0,
                CreateDisposition.FILE_OPEN,
                CreateOptions.FILE_NON_DIRECTORY_FILE |
                CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT)

    return pipe


class FSCTLPipeWait(Structure):
    """
    [MS-FSCC] 2.3.31 FSCTL_PIPE_WAIT Request

    The FSCTL_PIPE_WAIT Request requests that the server wait until either a
    time-out interval elapses or an instance of the specified named pipe is
    available for connection.
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('timeout', IntField(size=8)),
            ('name_length', IntField(
                size=4,
                default=lambda s: len(s['name'])
            )),
            ('timeout_specified', BoolField(
                size=1,
                default=lambda s: s['timeout'].get_value() > 0
            )),
            ('padding', IntField(size=1)),
            ('name', BytesField(
                size=lambda s: s['name_length'].get_value()
            ))
        ])
        super(FSCTLPipeWait, self).__init__()


class _NamedPipe(threading.Thread):

    ACCESS_MASK = 0

    def __init__(self, tree, name):
        super(_NamedPipe, self).__init__()
        log.info("Initialising Named Pipe with the name: %s" % name)
        self.name = name
        self.connection = tree.session.connection
        self.sid = tree.session.session_id
        self.tid = tree.tree_connect_id
        self.pipe = open_pipe(tree, name,
                              self.ACCESS_MASK,
                              fsctl_wait=True)

    def _close_thread(self):
        self.join(timeout=5)
        if self.is_alive():
            warnings.warn("Timeout while waiting for pipe thread to close: %s"
                          % self.name, TheadCloseTimeoutWarning)


class InputPipe(_NamedPipe):

    ACCESS_MASK = FilePipePrinterAccessMask.FILE_WRITE_DATA | \
                  FilePipePrinterAccessMask.FILE_APPEND_DATA | \
                  FilePipePrinterAccessMask.FILE_WRITE_EA | \
                  FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES | \
                  FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
                  FilePipePrinterAccessMask.READ_CONTROL | \
                  FilePipePrinterAccessMask.SYNCHRONIZE

    def __init__(self, tree, name):
        super(InputPipe, self).__init__(tree, name)
        self.pipe_buffer = Queue()
        self.close_bytes = os.urandom(16)
        log.debug("Shutdown bytes for input pipe: %s"
                  % binascii.hexlify(self.close_bytes))
        self.pipe_buffer = Queue()

    def run(self):
        try:
            log.debug("Starting thread of Input Named Pipe: %s" % self.name)
            while True:
                log.debug("Waiting for input for %s" % self.name)
                input_data = self.pipe_buffer.get()
                log.debug("Input for %s was found: %s"
                          % (self.name, binascii.hexlify(input_data)))
                if input_data == self.close_bytes:
                    log.debug("Close bytes was received for input pipe: %s"
                              % self.name)
                    break

                log.debug("Writing bytes to Input Named Pipe: %s" % self.name)
                self.pipe.write(input_data, 0)
        finally:
            log.debug("Closing SMB Open to Input Named Pipe: %s" % self.name)
            self.pipe.close(get_attributes=False)
        log.debug("Input Named Pipe %s thread finished" % self.name)

    def close(self):
        log.info("Closing Input Named Pipe: %s" % self.name)
        log.debug("Send shutdown bytes to Input Named Pipe: %s" % self.name)
        self.pipe_buffer.put(self.close_bytes)
        self._close_thread()


class OutputPipe(with_metaclass(ABCMeta, _NamedPipe)):

    ACCESS_MASK = FilePipePrinterAccessMask.FILE_READ_DATA | \
                  FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
                  FilePipePrinterAccessMask.FILE_READ_EA | \
                  FilePipePrinterAccessMask.READ_CONTROL | \
                  FilePipePrinterAccessMask.SYNCHRONIZE

    def __init__(self, tree, name):
        """Generic Output/Read Pipe that stores the output read in a Queue"""
        super(OutputPipe, self).__init__(tree, name)
        self.sent_first = False

    def run(self):
        # read from the pipe and close it at the end
        try:
            log.debug("Starting thread of Output Named Pipe: %s" % self.name)
            while True:
                # get the read request and sent it so we can let the parent
                # thread know it can continue before we are blocked by the read
                read_msg, read_resp_func = self.pipe.read(0, 1024, send=False)
                log.debug("Sending SMB Read request for Output Named Pipe: %s"
                          % self.name)
                request = self.connection.send(read_msg,
                                               sid=self.sid,
                                               tid=self.tid)
                self.sent_first = True
                try:
                    log.debug("Reading SMB Read response for Output Named "
                              "Pipe: %s" % self.name)
                    pipe_out = read_resp_func(request)
                    log.debug("Received SMB Read response for Output Named "
                              "Pipe: %s" % self.name)
                    self.handle_output(pipe_out)
                except SMBResponseException as exc:
                    # if the error was the pipe was broken exit the loop
                    # otherwise the error is serious so throw it
                    close_errors = [
                        NtStatus.STATUS_PIPE_BROKEN,
                        NtStatus.STATUS_PIPE_CLOSING,
                        NtStatus.STATUS_PIPE_EMPTY,
                        NtStatus.STATUS_PIPE_DISCONNECTED
                    ]
                    if exc.status in close_errors:
                        log.debug("%s received for Output Named Pipe: %s, "
                                  "ending thread"
                                  % (str(exc.header['status']), self.name))
                        break
                    else:
                        raise exc
        finally:
            log.debug("Closing Output Named Pipe: %s" % self.name)
            self.pipe.close(get_attributes=False)
        log.debug("Output Named Pipe %s thread finished" % self.name)

    @abstractmethod
    def handle_output(self, output):
        """
        The method called in the running thread whenever any data was read
        from the Named Pipe.

        :param output: a byte string of the output that was received from the
            Named Pipe
        """
        pass  # pragma: no cover

    @abstractmethod
    def get_output(self):
        """
        Returns the stdout/stderr return value used in client.run_executable.

        :return: The return object to return as part of the stdout/stderr
            variable for client.run_executable
        """
        pass  # pragma: no cover

    def close(self):
        log.info("Closing Output Named Pipe: %s" % self.name)
        self._close_thread()


class OutputPipeBytes(OutputPipe):

    def __init__(self, tree, name):
        self.pipe_buffer = b""
        super(OutputPipeBytes, self).__init__(tree, name)

    def handle_output(self, output):
        self.pipe_buffer += output

    def get_output(self):
        return self.pipe_buffer
