# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct


class PypsexecException(Exception):
    pass


class PAExecException(PypsexecException):

    @property
    def msg_id(self):
        return self.args[0]

    @property
    def buffer(self):
        return self.args[1]

    @property
    def message(self):
        error_length = struct.unpack("<L", self.buffer[:4])[0] * 2
        error_msg = self.buffer[4:error_length + 4]
        return "Received exception from remote PAExec service: %s"\
               % (error_msg.decode('utf-16-le'))

    def __str__(self):
        return self.message


class SCMRException(PypsexecException):

    @property
    def function(self):
        return self.args[0]

    @property
    def return_code(self):
        return self.args[1]

    @property
    def error_msg(self):
        return self.args[2]

    @property
    def message(self):
        return "Exception calling %s. Code: %d, Msg: %s"\
               % (self.function, self.return_code, self.error_msg)

    def __str__(self):
        return self.message


class PDUException(PypsexecException):
    pass
