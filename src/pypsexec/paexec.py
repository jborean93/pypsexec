# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import os
import pkgutil
import struct

from collections import (
    OrderedDict,
)

from smbprotocol.structure import (
    BoolField,
    BytesField,
    EnumField,
    IntField,
    ListField,
    Structure,
    StructureField,
    DateTimeField,
)

from pypsexec.exceptions import PAExecException


def paexec_out_stream(buffer_size=4096):
    """
    Creates a generator to read the PAExec executable data as a bytes stream. Currently the version of the paexec.exe
    is at 1.27.

    https://www.poweradmin.com/paexec/paexec.exe

    :param buffer_size: The size of the buffer yielded
    :return:  (bytes, offset) = the butes and the offset of the bytes string
    """
    b_data = pkgutil.get_data('pypsexec', 'paexec.exe')
    byte_count = len(b_data)
    for i in range(0, byte_count, buffer_size):
        yield b_data[i:i + buffer_size], i


def get_unique_id(pid, computer_name):
    """
    https://github.com/poweradminllc/PAExec/blob/master/Remote.cpp#L1045-L1065
    DWORD RemMsg::GetUniqueID()

    Creates a unique ID based on the PID of the local host and the name of the
    local host. It is derived from the first 4 bytes of a UTF-16 Little Endian
    encoded computer name and the local PID xor'd together.

    This value is sent in the PAExecSettingsMsg to define the process details
    and also the PAExecResponseMsg to control the execution and results of
    the processed based on the settings.

    :param pid: (int) the process id of the current host
    :param computer_name: (str/unicode) of the current hostname
    :return: int of the unique ID derived from the PID and Computer Name
    """
    bcomp_name = computer_name.encode('utf-16-le')[:4]
    bcomp_name = bcomp_name + (b"\x00" * (4 - len(bcomp_name)))
    return pid ^ struct.unpack("<L", bcomp_name)[0]


class PAExecMsgId(object):
    """
    https://github.com/poweradminllc/PAExec/blob/master/stdafx.h#L52-L57
    The various ID's used by PAExec when sending messages to and from the
    remote service.
    """
    MSGID_SETTINGS = 1
    MSGID_RESP_SEND_FILES = 2
    MSGID_SENT_FILES = 3
    MSGID_OK = 4
    MSGID_START_APP = 5
    MSGID_FAILED = 6


class ProcessPriority(object):
    """
    https://msdn.microsoft.com/en-us/library/windows/desktop/ms683211(v=vs.85).aspx
    Set's the priority of the thread in the current process
    """
    ABOVE_NORMAL_PRIORITY_CLASS = 0x00008000
    BELOW_NORMAL_PRIORITY_CLASS = 0x00004000
    HIGH_PRIORITY_CLASS = 0x00000080
    IDLE_PRIORITY_CLASS = 0x00000040
    NORMAL_PRIORITY_CLASS = 0x00000020
    REALTIME_PRIORITY_CLASS = 0x00000100


class PAExecMsg(Structure):
    """
    Generic message from PAExec, the first 2 bytes denotes the Msg ID
    that tells the host the type of message it is and the buffer contents
    varies based on the type of message that is being sent of received.

    This is slightly different to the PAExecSettingsMsg as the data in the
    settings msg is xor'd to slightly obfuscate the data. The current buffer
    structures that have been defined are PAStartBuffer, PAReturnBuffer
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('msg_id', EnumField(
                size=2,
                enum_type=PAExecMsgId
            )),
            ('unique_id', IntField(size=4)),
            ('buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer'])
            )),
            ('buffer', BytesField(
                size=lambda s: s['buffer_length'].get_value()
            ))
        ])
        super(PAExecMsg, self).__init__()

    def check_resp(self):
        msg_id = self['msg_id'].get_value()
        if msg_id != PAExecMsgId.MSGID_OK:
            raise PAExecException(msg_id, self['buffer'].get_value())


class PAExecSettingsMsg(Structure):
    """
    Custom PAExecMsg structure that contains the settings used by PAExec to
    configure the remote process. The structure is different from the standard
    PAExecMsg as the values past the msg_id is xor'd and the initial XOR value
    is generated randomly and stored after the msg_id.

    This does not encrypt the data but rather scrambles it so that someone
    snooping on the network traffic isn't easily able to see the settings as it
    can contain the credentials of a user. SMB encryption should really be used
    in most cases if it is available as that actually encrypts the data.

    The buffer value contains the PAExecSettingsBuffer type that contains all
    the settings used by PAExec.
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('msg_id', EnumField(
                size=2,
                default=PAExecMsgId.MSGID_SETTINGS,
                enum_type=PAExecMsgId
            )),
            ('xor_val', IntField(
                size=4,
                default=os.urandom(4)
            )),
            ('unique_id', IntField(size=4)),
            ('buffer_len', IntField(size=4)),
            ('buffer', StructureField(
                structure_type=PAExecSettingsBuffer
            ))
        ])
        super(PAExecSettingsMsg, self).__init__()

    def pack(self):
        # need to xor the buffer as expected by PAExec
        xor_value = self['xor_val'].get_value()

        # the id, length and buffer itself is xor'd
        input_data = self['unique_id'].pack() + self['buffer_len'].pack() + \
            self['buffer'].pack()
        buffer = self._xor_data(xor_value, input_data)

        # build the final data structure
        data = self['msg_id'].pack()
        data += self['xor_val'].pack()
        data += buffer

        return data

    def unpack(self, data):
        # need to de-xor the buffer to get human readable values
        xor_value = struct.unpack("<L", data[2:6])[0]
        buffer = data[6:]
        buffer_data = self._xor_data(xor_value, buffer)

        unique_id = buffer_data[:4]
        buffer_len = buffer_data[4:8]
        structure_a = PAExecSettingsBuffer()
        structure_a.unpack(buffer_data[8:])

        self['msg_id'] = data[:2]
        self['xor_val'] = data[2:6]
        self['unique_id'] = unique_id
        self['buffer_len'] = buffer_len
        self['buffer'] = structure_a
        return b""

    def _xor_data(self, xor_value, data):
        buffer = b""
        next_bytes = data[:4]

        for i in range(0, len(data) - 4):
            int_value = struct.unpack("<L", next_bytes)[0]
            xored_value = int_value ^ xor_value
            new_bytes = struct.pack("<L", xored_value)
            buffer += new_bytes[:1]
            next_bytes = new_bytes[1:] + data[i + 4:i + 5]
            xor_value += 3

        int_value = struct.unpack("<L", next_bytes)[0]
        xored_value = int_value ^ xor_value
        new_bytes = struct.pack("<L", xored_value)
        buffer += new_bytes

        return buffer


class PAExecSettingsBuffer(Structure):
    """
    https://github.com/poweradminllc/PAExec/blob/master/stdafx.h#L132-L341
    A PAExec buffer that contains the settings used by the remote PAExec
    service to start a process. It contains a wide range of settings that can
    be configured such as the remote user as well as the executable and
    arguments used to start the process.

    All BytesFields in this structure are utf-16-le encoded strings and should
    be encoded before setting in the structure.
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('version', IntField(
                size=4,
                default=1
            )),
            ('num_processors', IntField(
                size=4,
                default=lambda s: len(s['processors'].get_value())
            )),
            ('processors', ListField(
                size=lambda s: s['num_processors'].get_value() * 4,
                list_count=lambda s: s['num_processors'].get_value(),
                list_type=IntField(size=4)
            )),
            ('copy_files', BoolField(size=1)),
            ('force_copy', BoolField(size=1)),
            ('copy_if_newer_or_higher_ver', BoolField(size=1)),
            ('asynchronous', BoolField(size=1)),
            ('dont_load_profile', BoolField(size=1)),
            ('interactive_session', IntField(size=4)),
            ('interactive', BoolField(size=1)),
            ('run_elevated', BoolField(size=1)),
            ('run_limited', BoolField(size=1)),
            ('password_len', IntField(
                size=4,
                default=lambda s: int(len(s['password']) / 2)
            )),
            ('password', BytesField(
                size=lambda s: s['password_len'].get_value() * 2
            )),
            ('username_len', IntField(
                size=4,
                default=lambda s: int(len(s['username']) / 2)
            )),
            ('username', BytesField(
                size=lambda s: s['username_len'].get_value() * 2
            )),
            ('use_system_account', BoolField(size=1)),
            ('working_dir_len', IntField(
                size=4,
                default=lambda s: int(len(s['working_dir']) / 2)
            )),
            ('working_dir', BytesField(
                size=lambda s: s['working_dir_len'].get_value() * 2
            )),
            ('show_ui_on_win_logon', BoolField(size=1)),
            ('priority', EnumField(
                size=4,
                default=ProcessPriority.NORMAL_PRIORITY_CLASS,
                enum_type=ProcessPriority
            )),
            ('executable_len', IntField(
                size=4,
                default=lambda s: int(len(s['executable']) / 2)
            )),
            ('executable', BytesField(
                size=lambda s: s['executable_len'].get_value() * 2
            )),
            ('arguments_len', IntField(
                size=4,
                default=lambda s: int(len(s['arguments']) / 2)
            )),
            ('arguments', BytesField(
                size=lambda s: s['arguments_len'].get_value() * 2
            )),
            ('disable_file_redirection', BoolField(size=1)),
            ('enable_debug', BoolField(size=1)),
            ('remote_log_path_len', IntField(
                size=4,
                default=lambda s: int(len(s['remote_log_path']) / 2)
            )),
            ('remote_log_path', BytesField(
                size=lambda s: s['remote_log_path_len'].get_value() * 2
            )),
            ('no_delete', BoolField(size=1)),
            ('src_dir_len', IntField(
                size=4,
                default=lambda s: int(len(s['src_dir']) / 2)
            )),
            ('src_dir', BytesField(
                size=lambda s: s['src_dir_len'].get_value() * 2
            )),
            ('dest_dir_len', IntField(
                size=4,
                default=lambda s: int(len(s['dest_dir']) / 2)
            )),
            ('dest_dir', BytesField(
                size=lambda s: s['dest_dir_len'].get_value() * 2
            )),
            ('num_src_files', IntField(
                size=4,
                default=lambda s: len(s['src_files'].get_value())
            )),
            ('src_files', ListField(
                list_count=lambda s: s['num_src_files'].get_value(),
                list_type=StructureField(structure_type=PAExecFileInfo),
                unpack_func=lambda s, d:
                self._unpack_file_list(s, d, 'num_src_files')
            )),
            ('num_dest_files', IntField(
                size=4,
                default=lambda s: len(s['dest_files'].get_value())
            )),
            ('dest_files', ListField(
                list_count=lambda s: s['num_dest_files'].get_value(),
                list_type=StructureField(structure_type=PAExecFileInfo),
                unpack_func=lambda s, d:
                self._unpack_file_list(s, d, 'num_dest_files')
            )),
            ('timeout_seconds', IntField(size=4))
        ])
        super(PAExecSettingsBuffer, self).__init__()

    def _unpack_file_list(self, structure, data, len_field):
        files = []
        remaining_data = data
        for i in range(0, structure[len_field].get_value()):
            file_structure, remaining_data = self._get_file(remaining_data)
            files.append(file_structure)
        return files

    def _get_file(self, data):
        min_size = 21
        filename_size = struct.unpack("<L", data[:4])[0]
        structure_end_offset = min_size + (filename_size * 2)

        file_structure_data = data[:structure_end_offset]
        file_structure = PAExecFileInfo()
        file_structure.unpack(file_structure_data)
        return file_structure, data[structure_end_offset:]


class PAExecFileInfo(Structure):
    """
    https://github.com/poweradminllc/PAExec/blob/master/stdafx.h#L59-L82
    class FileInfo

    Structure the contains information about a file to copy or move and is set
    in PAExecSettingsBuffer. Like other PAExec messages, fields that take in a
    string take in a utf-16-le encoded string as a bytes structure.
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('filename_len', IntField(
                size=4,
                default=lambda s: int(len(s['filename']) / 2)
            )),
            ('filename', BytesField(
                size=lambda s: s['filename_len'].get_value() * 2
            )),
            ('file_last_write', DateTimeField(size=8)),
            ('file_version_ls', IntField(size=4)),
            ('file_version_ms', IntField(size=4)),
            ('copy_file', BoolField(size=1))
        ])
        super(PAExecFileInfo, self).__init__()


class PAExecStartBuffer(Structure):
    """
    Can't find where this is explicitly defined but this is the buffer used in
    the PAExecMsg to start a remote process. On receipt of this message, the
    remote process will match the settings based on the unique_id passed in and
    start the process based on those settings.

    The comp_name is a utf-16-le encoded string of the local hostname and
    should match the host used in the service name.
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('process_id', IntField(size=4)),
            ('comp_name_length', IntField(
                size=4,
                default=lambda s: int(len(s['comp_name']) / 2)
            )),
            ('comp_name', BytesField(
                size=lambda s: s['comp_name_length'].get_value() * 2
            ))
        ])
        super(PAExecStartBuffer, self).__init__()


class PAExecReturnBuffer(Structure):
    """
    The buffer used in the PAExecMsg that is sent by the remote service on
    completion of the remote process. It contains a single Int32 value that is
    the return code of the process.
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('return_code', IntField(size=4))
        ])
        super(PAExecReturnBuffer, self).__init__()
