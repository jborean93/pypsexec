# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import logging

from collections import (
    OrderedDict,
)

from smbclient import (
    open_file,
)

from smbprotocol import (
    MAX_PAYLOAD_SIZE,
)

from smbprotocol.ioctl import (
    CtlCode,
    IOCTLFlags,
    SMB2IOCTLRequest,
)

from smbprotocol.structure import (
    BoolField,
    IntField,
    Structure,
    TextField,
)


log = logging.getLogger(__name__)


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
            ('name', TextField(
                encoding='utf-16-le',
                size=lambda s: s['name_length'].get_value()
            ))
        ])
        super(FSCTLPipeWait, self).__init__()


def read_pipe(tree, name, out_buffer):
    """
    Opens a named pipe and reads the pipe bytes to the output buffer specified.

    :param tree: An opened SMB tree to the IPC$ share.
    :param name: The name of the named pipe to connect to.
    :param out_buffer: A write IO stream that accepts bytes that contains the pipe data.
    """
    log.debug("Starting output pipe listener for '%s'" % name)
    with _open_pipe(tree, name, 'rb') as pipe:
        while True:
            pipe_out = pipe.read(MAX_PAYLOAD_SIZE)
            if pipe_out == b"":
                log.debug("Output pipe listener for '%s' is empty, stopping listener" % name)
                return
            out_buffer.write(pipe_out)


def write_pipe(tree, name, in_buffer):
    """
    Opens a named pipe and writes the input buffer bytes to the named pipe specified.

    :param tree: An opened SMB tree to the IPC$ share.
    :param name: The name of the named pipe to connect to.
    :param in_buffer: A read IO stream that reads bytes to send to the named pipe.
    """
    log.debug("Starting input pipe listener for '%s'" % name)
    with _open_pipe(tree, name, 'wb') as pipe:
        while True:
            pipe_in = in_buffer.read(MAX_PAYLOAD_SIZE)
            if pipe_in == b"":
                log.debug("Input pipe listener for '%s' is empty, stopping listener" % name)
                return
            pipe.write(pipe_in)


def _open_pipe(tree, name, mode):
    """ Opens a pipe after making sure it is accepting connections. """
    wait_pipe = SMB2IOCTLRequest()
    wait_pipe['ctl_code'] = CtlCode.FSCTL_PIPE_WAIT
    wait_pipe['file_id'] = b"\xff" * 16
    wait_pipe['flags'] = IOCTLFlags.SMB2_0_IOCTL_IS_FSCTL

    fsctl_data = FSCTLPipeWait()
    fsctl_data['name'] = name
    wait_pipe['buffer'] = fsctl_data

    connection = tree.session.connection
    pipe_path = r"\\%s\IPC$\%s" % (connection.server_name, name)
    log.info("Sending FSCTL_PIPE_WAIT and opening named pipe at '%s'" % pipe_path)
    log.debug("%s\n%s" % (str(wait_pipe), str(fsctl_data)))
    request = connection.send(wait_pipe, sid=tree.session.session_id, tid=tree.tree_connect_id)
    connection.receive(request)

    return open_file(pipe_path, mode=mode, buffering=0, file_type='pipe')
