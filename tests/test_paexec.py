import pytest

from pypsexec.exceptions import PAExecException
from pypsexec.paexec import PAExecMsg, PAExecMsgId, get_unique_id


def test_get_unique_id():
    comp_name = "ABCDEF"
    pid = 1234
    expected = 4326547
    actual = get_unique_id(pid, comp_name)
    assert actual == expected


def test_get_unique_id_short_hostname():
    comp_name = "A"
    pid = 1234
    expected = 1171
    actual = get_unique_id(pid, comp_name)
    assert actual == expected


class TestPAExecMsgId(object):

    def test_create_message(self):
        message = PAExecMsg()
        message['msg_id'] = PAExecMsgId.MSGID_OK
        message['unique_id'] = 1234
        message['buffer'] = b"\x01\x02\x03\x04"
        expected = b"\x04\x00" \
                   b"\xd2\x04\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 14
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecMsg()
        data = b"\x04\x00" \
               b"\xd2\x04\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 14
        assert data == b""
        assert actual['msg_id'].get_value() == PAExecMsgId.MSGID_OK
        assert actual['unique_id'].get_value() == 1234
        assert actual['buffer_length'].get_value() == 4
        assert actual['buffer'].get_value() == b"\x01\x02\x03\x04"
        actual.check_resp()

    def test_parse_message_fail_response(self):
        actual = PAExecMsg()
        data = b"\x06\x00" \
               b"\xd2\x04\x00\x00" \
               b"\x08\x00\x00\x00" \
               b"\x04\x00\x00\x00\x68\x00\x69\x00"
        actual.unpack(data)
        with pytest.raises(PAExecException) as exc:
            actual.check_resp()
        assert str(exc.value) == "Received exception from remote PAExec " \
                                 "service: hi"
        assert exc.value.msg_id == PAExecMsgId.MSGID_FAILED
        assert exc.value.buffer == b"\x04\x00\x00\x00\x68\x00\x69\x00"
