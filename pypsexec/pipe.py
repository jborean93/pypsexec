import os
import sys
import threading

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
        self.pipe_buffer = Queue()
        self.name = name
        self.connection = tree.session.connection
        self.sid = tree.session.session_id
        self.tid = tree.tree_connect_id
        self.pipe = Open(tree, name)
        self._connect_pipe()

    def _connect_pipe(self):
        """
        Waits until the NamedPipe requested is available and connect to it
        so it is ready to send/receive data
        """
        wait_pipe = SMB2IOCTLRequest()
        wait_pipe['ctl_code'] = CtlCode.FSCTL_PIPE_WAIT
        wait_pipe['file_id'] = b"\xff" * 16
        wait_pipe['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

        fsctl_data = FSCTLPipeWait()
        fsctl_data['name'] = self.name.encode('utf-16-le')
        wait_pipe['buffer'] = fsctl_data

        request = self.connection.send(wait_pipe, sid=self.sid, tid=self.tid)
        self.connection.receive(request)

        # now open the Pipe
        self.pipe.open(ImpersonationLevel.Impersonation,
                       self.ACCESS_MASK,
                       FileAttributes.FILE_ATTRIBUTE_NORMAL,
                       0,
                       CreateDisposition.FILE_OPEN,
                       CreateOptions.FILE_NON_DIRECTORY_FILE |
                       CreateOptions.FILE_SYNCHRONOUS_IO_NONALERT)


class InputPipe(_NamedPipe):

    ACCESS_MASK = FilePipePrinterAccessMask.FILE_WRITE_DATA | \
                  FilePipePrinterAccessMask.FILE_APPEND_DATA | \
                  FilePipePrinterAccessMask.FILE_WRITE_EA | \
                  FilePipePrinterAccessMask.FILE_WRITE_ATTRIBUTES | \
                  FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
                  FilePipePrinterAccessMask.READ_CONTROL | \
                  FilePipePrinterAccessMask.SYNCHRONIZE

    def __init__(self, tree, name):
        self.close_bytes = os.urandom(16)
        super(InputPipe, self).__init__(tree, name)

    def run(self):
        try:
            while True:
                input_data = self.pipe_buffer.get()
                if input_data == self.close_bytes:
                    break

                self.pipe.write(input_data, 0, wait=True)
        finally:
            self.pipe.close(get_attributes=False)

    def close(self):
        self.pipe_buffer.put(self.close_bytes)
        self.join()
        self.pipe.close()


class OutputPipe(_NamedPipe):

    ACCESS_MASK = FilePipePrinterAccessMask.FILE_READ_DATA | \
                  FilePipePrinterAccessMask.FILE_READ_ATTRIBUTES | \
                  FilePipePrinterAccessMask.FILE_READ_EA | \
                  FilePipePrinterAccessMask.READ_CONTROL | \
                  FilePipePrinterAccessMask.SYNCHRONIZE

    def __init__(self, tree, name):
        super(OutputPipe, self).__init__(tree, name)

    def run(self):
        # read from the pipe and close it at the end
        try:
            sent_first = False
            while True:
                # get the read request and sent it so we can let the parent
                # thread know it can continue before we are blocked by the read
                read_msg, read_resp_func = self.pipe.read(0, 1024, send=False)
                request = self.connection.send(read_msg,
                                               sid=self.sid,
                                               tid=self.tid)
                if not sent_first:
                    self.pipe_buffer.put(None)
                    sent_first = True

                try:
                    pipe_out = read_resp_func(request, wait=True)
                    self.pipe_buffer.put(pipe_out)
                except SMBResponseException as exc:
                    # if the error was the pipe was broken exit the loop
                    # otherwise the error is serious so throw it
                    if exc.status == NtStatus.STATUS_PIPE_BROKEN:
                        break
                    else:
                        raise exc
        finally:
            self.pipe.close(get_attributes=False)

    def close(self):
        self.join()
        self.pipe.close(False)
