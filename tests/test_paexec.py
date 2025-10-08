# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)
import os.path
import pkgutil
import pytest

from datetime import (
    datetime, timezone,
)

from pypsexec.exceptions import (
    PAExecException,
)

from pypsexec.paexec import (
    PAExecFileInfo,
    PAExecMsg,
    PAExecMsgId,
    PAExecSettingsBuffer,
    PAExecSettingsMsg,
    PAExecStartBuffer,
    PAExecReturnBuffer,
    ProcessPriority,
    paexec_out_stream,
    get_unique_id,
)


def test_paexec_out_stream():
    actual = b""
    for data, offset in paexec_out_stream(None, 4096):
        actual += data

    assert actual == pkgutil.get_data("pypsexec", os.path.join("resources", "paexec.exe"))


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


class TestPAExecMsg(object):

    def test_create_message(self):
        message = PAExecMsg()
        message["msg_id"] = PAExecMsgId.MSGID_OK
        message["unique_id"] = 1234
        message["buffer"] = b"\x01\x02\x03\x04"
        expected = (
            b"\x04\x00" b"\xd2\x04\x00\x00" b"\x04\x00\x00\x00" b"\x01\x02\x03\x04"
        )
        actual = message.pack()
        assert len(message) == 14
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecMsg()
        data = b"\x04\x00" b"\xd2\x04\x00\x00" b"\x04\x00\x00\x00" b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 14
        assert data == b""
        assert actual["msg_id"].get_value() == PAExecMsgId.MSGID_OK
        assert actual["unique_id"].get_value() == 1234
        assert actual["buffer_length"].get_value() == 4
        assert actual["buffer"].get_value() == b"\x01\x02\x03\x04"
        actual.check_resp()

    def test_parse_message_fail_response(self):
        actual = PAExecMsg()
        data = (
            b"\x06\x00"
            b"\xd2\x04\x00\x00"
            b"\x08\x00\x00\x00"
            b"\x04\x00\x00\x00\x68\x00\x69\x00"
        )
        actual.unpack(data)
        with pytest.raises(PAExecException) as exc:
            actual.check_resp()
        assert str(exc.value) == "Received exception from remote PAExec " "service: hi"
        assert exc.value.msg_id == PAExecMsgId.MSGID_FAILED
        assert exc.value.buffer == b"\x04\x00\x00\x00\x68\x00\x69\x00"


class TestPAExecSettingsMsg(object):

    def test_create_message(self):
        message = PAExecSettingsMsg()
        message["msg_id"] = PAExecMsgId.MSGID_SETTINGS
        message["xor_val"] = b"\x01\x02\x03\x04"
        message["unique_id"] = 1

        buffer = PAExecSettingsBuffer()
        buffer["processors"] = [1, 2]
        buffer["interactive"] = True
        buffer["password"] = "pass".encode("utf-16-le")
        buffer["username"] = "user".encode("utf-16-le")
        buffer["executable"] = "a.exe".encode("utf-16-le")
        buffer["arguments"] = "arg1".encode("utf-16-le")
        buffer["src_dir"] = "C:\\source".encode("utf-16-le")
        buffer["dest_dir"] = "C:\\target".encode("utf-16-le")

        src_file_info1 = PAExecFileInfo()
        src_file_info1["filename"] = "src1".encode("utf-16-le")
        src_file_info1["file_last_write"] = datetime.utcfromtimestamp(0)
        src_file_info2 = PAExecFileInfo()
        src_file_info2["filename"] = "src2".encode("utf-16-le")
        src_file_info2["file_last_write"] = datetime.utcfromtimestamp(0)
        buffer["src_files"] = [src_file_info1, src_file_info2]

        dest_file_info1 = PAExecFileInfo()
        dest_file_info1["filename"] = "dest1".encode("utf-16-le")
        dest_file_info1["file_last_write"] = datetime.utcfromtimestamp(0)
        dest_file_info2 = PAExecFileInfo()
        dest_file_info2["filename"] = "dest2".encode("utf-16-le")
        dest_file_info2["file_last_write"] = datetime.utcfromtimestamp(0)
        buffer["dest_files"] = [dest_file_info1, dest_file_info2]
        message["buffer"] = buffer
        expected = (
            b"\x01\x00"
            b"\x01\x02\x03\x04"
            b"\x00\x06\x06\x0f\x08\x15\x16\x13"
            b"\x1d\x19\x1a\x27\x22\x2d\x2e\x2b"
            b"\x35\x31\x32\x3f\x3a\x45\x46\x43"
            b"\x4c\x49\x4a\x57\x50\x5d\x5e\x5b"
            b"\x64\x60\x62\x6f\x6c\x75\x76\x73"
            b"\x0c\x79\x1b\x87\xf3\x8d\xfd\x8b"
            b"\x90\x91\x92\x9f\xed\xa5\xd5\xa3"
            b"\xc9\xa9\xd8\xb7\xb0\xbd\xbe\xbb"
            b"\xc4\xc1\xe2\xcf\xc8\xd5\xd3\xd3"
            b"\xdc\xd9\xbb\xe7\xce\xed\x8b\xeb"
            b"\x8c\xf1\x97\xff\xfc\x05\x07\x02"
            b"\x6c\x08\x79\x16\x76\x1c\x2e\x1a"
            b"\x25\x20\x23\x2e\x29\x34\x37\x3b"
            b"\x3d\x38\x3b\x05\x41\x76\x4f\x16"
            b"\x55\x23\x53\x31\x59\x11\x67\x10"
            b"\x6d\x0b\x6b\x13\x71\x75\x7f\x7a"
            b"\x85\xc3\x83\xb4\x89\xc8\x97\xe6"
            b"\x9d\xf9\x9b\xd4\xa1\xcb\xaf\xcf"
            b"\xb5\xc4\xb3\xbc\xb9\xc4\xc7\xc6"
            b"\xcd\xc8\xcb\xa5\xd1\xae\xdf\xb9"
            b"\xe5\xd1\xe3\xee\x69\xca\x22\x2c"
            b"\x4c\x65\xfa\x06\x06\x0b\x08\x0d"
            b"\x12\x17\x14\x19\x1a\x23\x20\x25"
            b"\x59\x2f\x5e\x31\x55\x3b\x0a\x3d"
            b"\x42\xc7\x7a\x9c\x90\xe2\xcd\x54"
            b"\x5a\x5f\x5c\x61\x66\x6b\x68\x6d"
            b"\x72\x75\x74\x79\x7e\x86\x80\x85"
            b"\x8a\xeb\x8c\xf4\x96\xe8\x98\xe9"
            b"\xa2\x96\xa4\xa9\x2e\x8d\x65\x6b"
            b"\x0b\x22\xbd\xc1\xc6\xcb\xc8\xcd"
            b"\xd2\xd7\xd4\xd9\xdb\xe3\xe0\xe5"
            b"\x8e\xef\x89\xf1\x85\xfb\x8c\xfd"
            b"\x30\x06\x05\x88\x31\xc7\xcf\xa5"
            b"\x86\x1f\x1d\x20\x27\x2a\x29\x2c"
            b"\x33\x36\x35\x38\x02\x07\x04"
        )
        actual = message.pack()
        assert len(message) == 285
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecSettingsMsg()
        data = (
            b"\x01\x00"
            b"\x01\x02\x03\x04"
            b"\x00\x06\x06\x0f\x08\x15\x16\x13"
            b"\x1d\x19\x1a\x27\x22\x2d\x2e\x2b"
            b"\x35\x31\x32\x3f\x3a\x45\x46\x43"
            b"\x4c\x49\x4a\x57\x50\x5d\x5e\x5b"
            b"\x64\x60\x62\x6f\x6c\x75\x76\x73"
            b"\x0c\x79\x1b\x87\xf3\x8d\xfd\x8b"
            b"\x90\x91\x92\x9f\xed\xa5\xd5\xa3"
            b"\xc9\xa9\xd8\xb7\xb0\xbd\xbe\xbb"
            b"\xc4\xc1\xe2\xcf\xc8\xd5\xd3\xd3"
            b"\xdc\xd9\xbb\xe7\xce\xed\x8b\xeb"
            b"\x8c\xf1\x97\xff\xfc\x05\x07\x02"
            b"\x6c\x08\x79\x16\x76\x1c\x2e\x1a"
            b"\x25\x20\x23\x2e\x29\x34\x37\x3b"
            b"\x3d\x38\x3b\x05\x41\x76\x4f\x16"
            b"\x55\x23\x53\x31\x59\x11\x67\x10"
            b"\x6d\x0b\x6b\x13\x71\x75\x7f\x7a"
            b"\x85\xc3\x83\xb4\x89\xc8\x97\xe6"
            b"\x9d\xf9\x9b\xd4\xa1\xcb\xaf\xcf"
            b"\xb5\xc4\xb3\xbc\xb9\xc4\xc7\xc6"
            b"\xcd\xc8\xcb\xa5\xd1\xae\xdf\xb9"
            b"\xe5\xd1\xe3\xee\x69\xca\x22\x2c"
            b"\x4c\x65\xfa\x06\x06\x0b\x08\x0d"
            b"\x12\x17\x14\x19\x1a\x23\x20\x25"
            b"\x59\x2f\x5e\x31\x55\x3b\x0a\x3d"
            b"\x42\xc7\x7a\x9c\x90\xe2\xcd\x54"
            b"\x5a\x5f\x5c\x61\x66\x6b\x68\x6d"
            b"\x72\x75\x74\x79\x7e\x86\x80\x85"
            b"\x8a\xeb\x8c\xf4\x96\xe8\x98\xe9"
            b"\xa2\x96\xa4\xa9\x2e\x8d\x65\x6b"
            b"\x0b\x22\xbd\xc1\xc6\xcb\xc8\xcd"
            b"\xd2\xd7\xd4\xd9\xdb\xe3\xe0\xe5"
            b"\x8e\xef\x89\xf1\x85\xfb\x8c\xfd"
            b"\x30\x06\x05\x88\x31\xc7\xcf\xa5"
            b"\x86\x1f\x1d\x20\x27\x2a\x29\x2c"
            b"\x33\x36\x35\x38\x02\x07\x04"
        )
        data = actual.unpack(data)
        assert len(actual) == 285
        assert data == b""
        assert actual["msg_id"].get_value() == PAExecMsgId.MSGID_SETTINGS
        assert actual["xor_val"].get_value() == 67305985
        assert actual["unique_id"].get_value() == 1
        assert actual["buffer_len"].get_value() == 0
        actual = actual["buffer"].get_value()
        assert actual["version"].get_value() == 1
        assert actual["num_processors"].get_value() == 2
        processors = actual["processors"].get_value()
        assert len(processors) == 2
        assert processors[0] == 1
        assert processors[1] == 2
        assert not actual["copy_files"].get_value()
        assert not actual["force_copy"].get_value()
        assert not actual["copy_if_newer_or_higher_ver"].get_value()
        assert not actual["asynchronous"].get_value()
        assert not actual["dont_load_profile"].get_value()
        assert actual["interactive_session"].get_value() == 0
        assert actual["interactive"].get_value()
        assert not actual["run_elevated"].get_value()
        assert not actual["run_limited"].get_value()
        assert actual["password_len"].get_value() == 4
        assert actual["password"].get_value() == "pass".encode("utf-16-le")
        assert actual["username_len"].get_value() == 4
        assert actual["username"].get_value() == "user".encode("utf-16-le")
        assert not actual["use_system_account"].get_value()
        assert actual["working_dir_len"].get_value() == 0
        assert actual["working_dir"].get_value() == b""
        assert not actual["show_ui_on_win_logon"].get_value()
        assert actual["priority"].get_value() == ProcessPriority.NORMAL_PRIORITY_CLASS
        assert actual["executable_len"].get_value() == 5
        assert actual["executable"].get_value() == "a.exe".encode("utf-16-le")
        assert actual["arguments_len"].get_value() == 4
        assert actual["arguments"].get_value() == "arg1".encode("utf-16-le")
        assert not actual["disable_file_redirection"].get_value()
        assert not actual["enable_debug"].get_value()
        assert actual["remote_log_path_len"].get_value() == 0
        assert actual["remote_log_path"].get_value() == b""
        assert not actual["no_delete"].get_value()
        assert actual["src_dir_len"].get_value() == 9
        assert actual["src_dir"].get_value() == "C:\\source".encode("utf-16-le")
        assert actual["dest_dir_len"].get_value() == 9
        assert actual["dest_dir"].get_value() == "C:\\target".encode("utf-16-le")
        assert actual["num_src_files"].get_value() == 2
        src_files = actual["src_files"].get_value()
        assert len(src_files) == 2
        assert src_files[0]["filename_len"].get_value() == 4
        assert src_files[0]["filename"].get_value() == "src1".encode("utf-16-le")
        assert src_files[0]["file_last_write"].get_value() == datetime.utcfromtimestamp(
            0
        ).replace(tzinfo=timezone.utc)
        assert src_files[0]["file_version_ls"].get_value() == 0
        assert src_files[0]["file_version_ms"].get_value() == 0
        assert not src_files[0]["copy_file"].get_value()
        assert src_files[1]["filename_len"].get_value() == 4
        assert src_files[1]["filename"].get_value() == "src2".encode("utf-16-le")
        assert src_files[1]["file_last_write"].get_value() == datetime.utcfromtimestamp(
            0
        ).replace(tzinfo=timezone.utc)
        assert src_files[1]["file_version_ls"].get_value() == 0
        assert src_files[1]["file_version_ms"].get_value() == 0
        assert not src_files[1]["copy_file"].get_value()
        assert actual["num_dest_files"].get_value() == 2
        dest_files = actual["dest_files"].get_value()
        assert len(dest_files) == 2
        assert dest_files[0]["filename_len"].get_value() == 5
        assert dest_files[0]["filename"].get_value() == "dest1".encode("utf-16-le")
        assert dest_files[0][
            "file_last_write"
        ].get_value() == datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
        assert dest_files[0]["file_version_ls"].get_value() == 0
        assert dest_files[0]["file_version_ms"].get_value() == 0
        assert not dest_files[0]["copy_file"].get_value()
        assert dest_files[1]["filename_len"].get_value() == 5
        assert dest_files[1]["filename"].get_value() == "dest2".encode("utf-16-le")
        assert dest_files[1][
            "file_last_write"
        ].get_value() == datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
        assert dest_files[1]["file_version_ls"].get_value() == 0
        assert dest_files[1]["file_version_ms"].get_value() == 0
        assert not dest_files[1]["copy_file"].get_value()
        assert actual["timeout_seconds"].get_value() == 0


class TestPAExecSettingsBuffer(object):

    def test_create_message(self):
        message = PAExecSettingsBuffer()
        message["processors"] = [1, 2]
        message["interactive"] = True
        message["password"] = "pass".encode("utf-16-le")
        message["username"] = "user".encode("utf-16-le")
        message["executable"] = "a.exe".encode("utf-16-le")
        message["arguments"] = "arg1".encode("utf-16-le")
        message["src_dir"] = "C:\\source".encode("utf-16-le")
        message["dest_dir"] = "C:\\target".encode("utf-16-le")

        src_file_info1 = PAExecFileInfo()
        src_file_info1["filename"] = "src1".encode("utf-16-le")
        src_file_info1["file_last_write"] = datetime.utcfromtimestamp(0)
        src_file_info2 = PAExecFileInfo()
        src_file_info2["filename"] = "src2".encode("utf-16-le")
        src_file_info2["file_last_write"] = datetime.utcfromtimestamp(0)
        message["src_files"] = [src_file_info1, src_file_info2]

        dest_file_info1 = PAExecFileInfo()
        dest_file_info1["filename"] = "dest1".encode("utf-16-le")
        dest_file_info1["file_last_write"] = datetime.utcfromtimestamp(0)
        dest_file_info2 = PAExecFileInfo()
        dest_file_info2["filename"] = "dest2".encode("utf-16-le")
        dest_file_info2["file_last_write"] = datetime.utcfromtimestamp(0)
        message["dest_files"] = [dest_file_info1, dest_file_info2]

        expected = (
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x01\x00\x00\x00\x02\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x00"
            b"\x00"
            b"\x04\x00\x00\x00"
            b"\x70\x00\x61\x00\x73\x00\x73\x00"
            b"\x04\x00\x00\x00"
            b"\x75\x00\x73\x00\x65\x00\x72\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x20\x00\x00\x00"
            b"\x05\x00\x00\x00"
            b"\x61\x00\x2e\x00\x65\x00\x78\x00"
            b"\x65\x00"
            b"\x04\x00\x00\x00"
            b"\x61\x00\x72\x00\x67\x00\x31\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x09\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x73\x00"
            b"\x6f\x00\x75\x00\x72\x00\x63\x00"
            b"\x65\x00"
            b"\x09\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x61\x00\x72\x00\x67\x00\x65\x00"
            b"\x74\x00"
            b"\x02\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x73\x00\x72\x00\x63\x00\x31\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x04\x00\x00\x00"
            b"\x73\x00\x72\x00\x63\x00\x32\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x05\x00\x00\x00"
            b"\x64\x00\x65\x00\x73\x00\x74\x00"
            b"\x31\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05\x00\x00\x00"
            b"\x64\x00\x65\x00\x73\x00\x74\x00"
            b"\x32\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
        )
        actual = message.pack()
        assert len(message) == 271
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecSettingsBuffer()
        data = (
            b"\x01\x00\x00\x00"
            b"\x02\x00\x00\x00"
            b"\x01\x00\x00\x00\x02\x00\x00\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x01"
            b"\x00"
            b"\x00"
            b"\x04\x00\x00\x00"
            b"\x70\x00\x61\x00\x73\x00\x73\x00"
            b"\x04\x00\x00\x00"
            b"\x75\x00\x73\x00\x65\x00\x72\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x20\x00\x00\x00"
            b"\x05\x00\x00\x00"
            b"\x61\x00\x2e\x00\x65\x00\x78\x00"
            b"\x65\x00"
            b"\x04\x00\x00\x00"
            b"\x61\x00\x72\x00\x67\x00\x31\x00"
            b"\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x09\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x73\x00"
            b"\x6f\x00\x75\x00\x72\x00\x63\x00"
            b"\x65\x00"
            b"\x09\x00\x00\x00"
            b"\x43\x00\x3a\x00\x5c\x00\x74\x00"
            b"\x61\x00\x72\x00\x67\x00\x65\x00"
            b"\x74\x00"
            b"\x02\x00\x00\x00"
            b"\x04\x00\x00\x00"
            b"\x73\x00\x72\x00\x63\x00\x31\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x04\x00\x00\x00"
            b"\x73\x00\x72\x00\x63\x00\x32\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x02\x00\x00\x00"
            b"\x05\x00\x00\x00"
            b"\x64\x00\x65\x00\x73\x00\x74\x00"
            b"\x31\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x05\x00\x00\x00"
            b"\x64\x00\x65\x00\x73\x00\x74\x00"
            b"\x32\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x00\x00\x00\x00"
            b"\x00\x00\x00\x00"
            b"\x00"
            b"\x00\x00\x00\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 271
        assert data == b""
        assert actual["version"].get_value() == 1
        assert actual["num_processors"].get_value() == 2
        processors = actual["processors"].get_value()
        assert len(processors) == 2
        assert processors[0] == 1
        assert processors[1] == 2
        assert not actual["copy_files"].get_value()
        assert not actual["force_copy"].get_value()
        assert not actual["copy_if_newer_or_higher_ver"].get_value()
        assert not actual["asynchronous"].get_value()
        assert not actual["dont_load_profile"].get_value()
        assert actual["interactive_session"].get_value() == 0
        assert actual["interactive"].get_value()
        assert not actual["run_elevated"].get_value()
        assert not actual["run_limited"].get_value()
        assert actual["password_len"].get_value() == 4
        assert actual["password"].get_value() == "pass".encode("utf-16-le")
        assert actual["username_len"].get_value() == 4
        assert actual["username"].get_value() == "user".encode("utf-16-le")
        assert not actual["use_system_account"].get_value()
        assert actual["working_dir_len"].get_value() == 0
        assert actual["working_dir"].get_value() == b""
        assert not actual["show_ui_on_win_logon"].get_value()
        assert actual["priority"].get_value() == ProcessPriority.NORMAL_PRIORITY_CLASS
        assert actual["executable_len"].get_value() == 5
        assert actual["executable"].get_value() == "a.exe".encode("utf-16-le")
        assert actual["arguments_len"].get_value() == 4
        assert actual["arguments"].get_value() == "arg1".encode("utf-16-le")
        assert not actual["disable_file_redirection"].get_value()
        assert not actual["enable_debug"].get_value()
        assert actual["remote_log_path_len"].get_value() == 0
        assert actual["remote_log_path"].get_value() == b""
        assert not actual["no_delete"].get_value()
        assert actual["src_dir_len"].get_value() == 9
        assert actual["src_dir"].get_value() == "C:\\source".encode("utf-16-le")
        assert actual["dest_dir_len"].get_value() == 9
        assert actual["dest_dir"].get_value() == "C:\\target".encode("utf-16-le")
        assert actual["num_src_files"].get_value() == 2
        src_files = actual["src_files"].get_value()
        assert len(src_files) == 2
        assert src_files[0]["filename_len"].get_value() == 4
        assert src_files[0]["filename"].get_value() == "src1".encode("utf-16-le")
        assert src_files[0]["file_last_write"].get_value() == datetime.utcfromtimestamp(
            0
        ).replace(tzinfo=timezone.utc)
        assert src_files[0]["file_version_ls"].get_value() == 0
        assert src_files[0]["file_version_ms"].get_value() == 0
        assert not src_files[0]["copy_file"].get_value()
        assert src_files[1]["filename_len"].get_value() == 4
        assert src_files[1]["filename"].get_value() == "src2".encode("utf-16-le")
        assert src_files[1]["file_last_write"].get_value() == datetime.utcfromtimestamp(
            0
        ).replace(tzinfo=timezone.utc)
        assert src_files[1]["file_version_ls"].get_value() == 0
        assert src_files[1]["file_version_ms"].get_value() == 0
        assert not src_files[1]["copy_file"].get_value()
        assert actual["num_dest_files"].get_value() == 2
        dest_files = actual["dest_files"].get_value()
        assert len(dest_files) == 2
        assert dest_files[0]["filename_len"].get_value() == 5
        assert dest_files[0]["filename"].get_value() == "dest1".encode("utf-16-le")
        assert dest_files[0][
            "file_last_write"
        ].get_value() == datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
        assert dest_files[0]["file_version_ls"].get_value() == 0
        assert dest_files[0]["file_version_ms"].get_value() == 0
        assert not dest_files[0]["copy_file"].get_value()
        assert dest_files[1]["filename_len"].get_value() == 5
        assert dest_files[1]["filename"].get_value() == "dest2".encode("utf-16-le")
        assert dest_files[1][
            "file_last_write"
        ].get_value() == datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
        assert dest_files[1]["file_version_ls"].get_value() == 0
        assert dest_files[1]["file_version_ms"].get_value() == 0
        assert not dest_files[1]["copy_file"].get_value()
        assert actual["timeout_seconds"].get_value() == 0


class TestPAExecFileInfo(object):

    def test_create_message(self):
        message = PAExecFileInfo()
        message["filename"] = "file".encode("utf-16-le")
        message["file_last_write"] = datetime.utcfromtimestamp(0)
        message["file_version_ls"] = 10
        message["file_version_ms"] = 10
        message["copy_file"] = True
        expected = (
            b"\x04\x00\x00\x00"
            b"\x66\x00\x69\x00\x6c\x00\x65\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x0a\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x01"
        )
        actual = message.pack()
        assert len(message) == 29
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecFileInfo()
        data = (
            b"\x04\x00\x00\x00"
            b"\x66\x00\x69\x00\x6c\x00\x65\x00"
            b"\x00\x80\x3e\xd5\xde\xb1\x9d\x01"
            b"\x0a\x00\x00\x00"
            b"\x0a\x00\x00\x00"
            b"\x01"
        )
        data = actual.unpack(data)
        assert len(actual) == 29
        assert data == b""
        assert actual["filename_len"].get_value() == 4
        assert actual["filename"].get_value() == "file".encode("utf-16-le-")
        assert actual["file_last_write"].get_value() == datetime.utcfromtimestamp(0).replace(tzinfo=timezone.utc)
        assert actual["file_version_ls"].get_value() == 10
        assert actual["file_version_ms"].get_value() == 10
        assert actual["copy_file"].get_value()


class TestPAExecStartBuffer(object):

    def test_create_message(self):
        message = PAExecStartBuffer()
        message["process_id"] = 1234
        message["comp_name"] = "comp".encode("utf-16-le")
        expected = (
            b"\xd2\x04\x00\x00" b"\x04\x00\x00\x00" b"\x63\x00\x6f\x00\x6d\x00\x70\x00"
        )
        actual = message.pack()
        assert len(message) == 16
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecStartBuffer()
        data = (
            b"\xd2\x04\x00\x00" b"\x04\x00\x00\x00" b"\x63\x00\x6f\x00\x6d\x00\x70\x00"
        )
        data = actual.unpack(data)
        assert len(actual) == 16
        assert data == b""
        assert actual["process_id"].get_value() == 1234
        assert actual["comp_name_length"].get_value() == 4
        assert actual["comp_name"].get_value() == "comp".encode("utf-16-le")


class TestPAExecReturnBuffer(object):

    def test_create_message(self):
        message = PAExecReturnBuffer()
        message["return_code"] = 10
        expected = b"\x0a\x00\x00\x00"
        actual = message.pack()
        assert len(actual) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = PAExecReturnBuffer()
        data = b"\x0a\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 4
        assert data == b""
        assert actual["return_code"].get_value() == 10
