# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest

from pypsexec.exceptions import (
    PAExecException,
    PDUException,
    PypsexecException,
    SCMRException,
)


class TestPypsexecException(object):

    def test_throw_pypsexec_exception(self):
        with pytest.raises(PypsexecException) as exc:
            raise PypsexecException("hi")
        assert str(exc.value) == "hi"


class TestPAExecException(object):

    def test_throw_paexec_exception(self):
        with pytest.raises(PAExecException) as exc:
            raise PAExecException(1, b"\x02\x00\x00\x00\x61\x00")
        exc_msg = "Received exception from remote PAExec service: a"
        assert str(exc.value) == exc_msg
        assert exc.value.msg_id == 1
        assert exc.value.buffer == b"\x02\x00\x00\x00\x61\x00"
        assert exc.value.message == exc_msg


class TestSCMRException(object):

    def test_scmr_exception(self):
        with pytest.raises(SCMRException) as exc:
            raise SCMRException("function_name", 1, "error_msg")
        exc_msg = "Exception calling function_name. Code: 1, Msg: error_msg"
        assert str(exc.value) == exc_msg
        assert exc.value.function == "function_name"
        assert exc.value.return_code == 1
        assert exc.value.error_msg == "error_msg"
        assert exc.value.message == exc_msg


class TestPDUException(object):

    def test_throw_pdu_exception(self):
        with pytest.raises(PDUException) as exc:
            raise PDUException("error_msg")
        assert str(exc.value) == "error_msg"
