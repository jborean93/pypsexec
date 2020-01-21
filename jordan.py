import smbclient
import struct

from collections import (
    OrderedDict,
)

from smbprotocol.change_notify import (
    CompletionFilter,
    FileSystemWatcher,
)

from smbprotocol.structure import (
    EnumField,
    IntField,
    Structure,
    StructureField,
    TextField,
)


class MessageType(object):
    ERROR_MSG = 0
    PROCESS_START_MSG = 1
    PROCESS_INFO_MSG = 2
    PROCESS_END_MSG = 3


class ServiceMsg(Structure):

    def __init__(self):
        self.fields = OrderedDict([
            ('type', EnumField(
                size=4,
                enum_type=MessageType,
            )),
            ('buffer_length', IntField(
                size=4,
                default=lambda s: len(s['buffer']),
            )),
            ('buffer', StructureField(
                size=lambda s: s['buffer_length'].get_value(),
                structure_type=lambda s: ServiceMsg._get_structure_type(s),
            )),
        ])
        super(ServiceMsg, self).__init__()

    @staticmethod
    def _get_structure_type(structure):
        return {
            MessageType.ERROR_MSG: ErrorMsg,
        }[structure['type'].get_value()]


class ErrorMsg(Structure):

    def __init__(self):
        self.fields = OrderedDict([
            ('error_code', IntField(size=4)),
            ('message_len', IntField(
                size=4,
                default=lambda s: len(s['message']),
            )),
            ('message', TextField(
                size=lambda s: s['message_len'].get_value(),
                encoding='utf-8',
            )),
        ])
        super(ErrorMsg, self).__init__()


def read_pipe(server, name):
    #with smbclient.open_file(r'\\%s\IPC$' % server, mode='rb', buffering=0, file_type='dir') as ipc_dir:
    #    pipe_watcher = FileSystemWatcher(ipc_dir.fd)
    #    pipe_watcher.start(CompletionFilter.FILE_NOTIFY_CHANGE_FILE_NAME)
    #    pipe_watcher.wait()

    buffer = 4096

    with smbclient.open_file(r'\\%s\IPC$\%s' % (server, name), mode='rb', file_type='pipe', buffering=0) as fd:
        data = fd.read(buffer)
        msg_len = struct.unpack("<I", data[:4])[0]
        data = data[4:]

        while len(data) != msg_len:
            data += fd.read(buffer)

        return data


server = 'server2019.domain.local'
smbclient.register_session(server, username='vagrant-domain@DOMAIN.LOCAL', password='VagrantPass1')

data = read_pipe(server, 'Jordan')

msg = ServiceMsg()
data = msg.unpack(data)

print(msg)
a = ''
