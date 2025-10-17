# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import struct

from collections import (
    OrderedDict,
)

from smbprotocol.structure import (
    BytesField,
    EnumField,
    FlagField,
    IntField,
    ListField,
    Structure,
    StructureField,
    UuidField,
)

from pypsexec.exceptions import (
    PDUException,
)


def parse_pdu(data):
    """
    Converts the raw byte string of PDU data into a *PDU() structure. If the
    type is invalid or unknown to pypsexec it will throw a PDUException.

    :param data: The byte string returned in the buffer of the IOCTL response
    :return: *PDU() structure that is dependent on the type being parsed
    """
    type = struct.unpack("<B", data[2:3])[0]  # third element is PType
    known_types = {
        PType.REQUEST: RequestPDU(),
        PType.RESPONSE: ResponsePDU(),
        PType.FAULT: FaultPDU(),
        PType.BIND: BindPDU(),
        PType.BIND_ACK: BindAckPDU(),
        PType.BIND_NAK: BindNakPDU(),
    }

    pdu = known_types.get(type, None)
    if not pdu:
        raise PDUException("Cannot parse PDU of type %s" % type)
    pdu.unpack(data)
    return pdu


class PFlags(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagtcjh_28

    Connection-oriented PDU Data Types
    """
    PFC_FIRST_FRAG = 0x01
    PFC_LAST_FRAG = 0x02
    PFC_PENDING_CANCEL = 0x04
    PFC_RESERVED_1 = 0x08
    PFC_CONC_MPX = 0x10
    PFC_DID_NOT_EXECUTE = 0x20
    PFC_MAYBE = 0x40
    PFC_OBJECT_UUID = 0x80


class PType(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm

    Table: RPC Protocol Data Unit
    Various RPC PDU Type values used in a PDU message
    """
    REQUEST = 0
    PING = 1
    RESPONSE = 2
    FAULT = 3
    WORKING = 4
    NOCALL = 6
    REJECT = 6
    ACK = 7
    CL_CANCEL = 8
    FACK = 9
    CANCEL_ACK = 10
    BIND = 11
    BIND_ACK = 12
    BIND_NAK = 13
    ALTER_CONTEXT = 14
    ALTER_CONTEXT_RESP = 15
    SHUTDOWN = 17
    CO_CANCEL = 18
    ORPHANED = 19


class IntegerCharacterRepresentation(object):
    ASCII_BIG_ENDIAN = 0x00
    ASCII_LITTLE_ENDIAN = 0x10
    EBCDIC_BIG_ENDIAN = 0x01
    EBCDIC_LITTLE_ENDIAN = 0x11


class FloatingPointRepresentation(object):
    IEEE = 0x0
    VAX = 0x1
    CRAY = 0x2
    IBM = 0x3


class ContextResult(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    p_cont_def_result_t
    """
    ACCEPTANCE = 0
    USER_REJECTION = 1
    PROVIDER_REJECTION = 2
    NEGOTIATE_ACK = 3  # not in spec but in MS-RPCE 2.2.2.4


class ResultReason(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    p_provider_reason_t
    """
    REASON_NOT_SPECIFIED = 0
    ABSTRACT_SYNTAX_NOT_SUPPORTED = 1
    PROPOSED_TRANSFER_SYNTAXES_NOT_SUPPORTED = 2
    LOCAL_LIMIT_EXCEEDED = 3


class BindNakReason(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    Reasons for rejection of an association are returned in the bind_nak PDU
    """
    REASON_NOT_SPECIFIED = 0
    TEMPORARY_CONGESTION = 1
    LOCAL_LIMIT_EXCEEDED = 2
    CALLED_PADDR_UNKNOWN = 3
    PROTOCOL_VERSION_NOT_SUPPORTED = 4
    DEFAULT_CONTEXT_NOT_SUPPORTED = 5
    USER_DATA_NOT_READABLE = 6
    NO_PSAP_AVAILABLE = 7


class FaultStatus(object):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/apdxe.htm#tagtcjh_43
    fault_status Parameter
    """
    RPC_S_FAULT_OBJECT_NOT_FOUND = 0x16C9A01B
    RPC_S_CALL_CANCELLED = 0x16C9A031
    RPC_S_FAULT_ADDR_ERROR = 0x16C9A074
    RPC_S_FAULT_CONTEXT_MISMATCH = 0x16C9A075
    RPC_S_FAULT_FP_DIV_BY_ZERO = 0x16C9A076
    RPC_S_FAULT_FP_ERROR = 0x16C9A077
    RPC_S_FAULT_FP_OVERFLOW = 0x16C9A078
    RPC_S_FAULT_FP_UNDERFLOW = 0x16C9A079
    RPC_S_FAULT_ILL_INST = 0x16C9A07A
    RPC_S_FAULT_INT_DIV_BY_ZERO = 0x16C9A07B
    RPC_S_FAULT_INT_OVERFLOW = 0x16C9A07C
    RPC_S_FAULT_INVALID_BOUND = 0x16C9A07D
    RPC_S_FAULT_INVALID_TAG = 0x16C9A07E
    RPC_S_FAULT_PIPE_CLOSED = 0x16C9A07F
    RPC_S_FAULT_PIPE_COMM_ERROR = 0x16C9A080
    RPC_S_FAULT_PIPE_DISCIPLINE = 0x16C9A081
    RPC_S_FAULT_PIPE_EMPTY = 0x16C9A082
    RPC_S_FAULT_PIPE_MEMORY = 0x16C9A083
    RPC_S_FAULT_PIPE_ORDER = 0x16C9A084
    RPC_S_FAULT_REMOTE_NO_MEMORY = 0x16C9A086
    RPC_S_FAULT_UNSPEC = 0x16C9A087
    RPC_S_FAULT_USER_DEFINED = 0x16C9A113
    RPC_S_FAULT_TX_OPEN_FAILED = 0x16C9A116
    RPC_S_FAULT_CODESET_CONV_ERROR = 0x16C9A16E
    RPC_S_FAULT_NO_CLIENT_STUB = 0x16C9A170
    NCA_S_FAULT_OBJECT_NOT_FOUND = 0x1C000024
    NCA_S_FAULT_CANCEL = 0x1C00000D
    NCA_S_FAULT_ADDR_ERROR = 0x1C000002
    NCA_S_FAULT_CONTEXT_MISMATCH = 0x1C00001A
    NCA_S_FAULT_FP_DIV_ZERO = 0x1C000003
    NCA_S_FAULT_FP_ERROR = 0x1C00000F
    NCA_S_FAULT_FP_OVERFLOW = 0x1C000005
    NCA_S_FAULT_FP_UNDERFLOW = 0x1C000004
    NCA_S_FAULT_ILL_INST = 0x1C00000E
    NCA_S_FAULT_INT_DIV_BY_ZERO = 0x1C000001
    NCA_S_FAULT_INT_OVERFLOW = 0x1C000010
    NCA_S_FAULT_INVALID_BOUND = 0x1C000007
    NCA_S_FAULT_INVALID_TAG = 0x1C000006
    NCA_S_FAULT_PIPE_CLOSED = 0x1C000015
    NCA_S_FAULT_PIPE_COMM_ERROR = 0x1C000018
    NCA_S_FAULT_PIPE_DISCIPLINE = 0x1C000017
    NCA_S_FAULT_PIPE_EMPTY = 0x1C000014
    NCA_S_FAULT_PIPE_MEMORY = 0x1C000019
    NCA_S_FAULT_PIPE_ORDER = 0x1C000016
    NCA_S_FAULT_REMOTE_NO_MEMORY = 0x1C00001B
    NCS_S_FAULT_USER_DEFINED = 0x1C000021
    NCA_S_FAULT_TX_OPEN_FAILED = 0x1C000022
    NCA_S_FAULT_CODESET_CONV_ERROR = 0x1C000023
    NCA_S_FAULT_NO_CLIENT_STUB = 0x1C000025
    NCA_S_FAULT_NDR = 0x000006F7


class DataRepresentationFormat(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap14.htm#tagcjh_19
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('integer_character', EnumField(
                size=1,
                enum_type=IntegerCharacterRepresentation,
                default=IntegerCharacterRepresentation.ASCII_LITTLE_ENDIAN
            )),
            ('floating_point', EnumField(
                size=1,
                enum_type=FloatingPointRepresentation,
                default=FloatingPointRepresentation.IEEE
            )),
            ('reserved1', IntField(size=1)),
            ('reserved2', IntField(size=1))
        ])
        super(DataRepresentationFormat, self).__init__()


class SyntaxIdElement(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    p_syntax_id_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('uuid', UuidField(little_endian=False)),
            ('version', IntField(size=4))
        ])
        super(SyntaxIdElement, self).__init__()


class ContextElement(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    p_cont_elem_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('context_id', IntField(size=2)),
            ('n_transfer_syn', IntField(
                size=1,
                default=lambda s: len(s['transfer_syntaxes'].get_value())
            )),
            ('reserved', IntField(size=1)),
            ('abstract_syntax', StructureField(
                structure_type=SyntaxIdElement
            )),
            ('transfer_syntaxes', ListField(
                list_type=StructureField(
                    size=20,
                    structure_type=SyntaxIdElement
                ),
                list_count=lambda s: s['n_transfer_syn'].get_value(),
                size=lambda s: s['n_transfer_syn'].get_value() * 20
            )),
        ])
        super(ContextElement, self).__init__()


class Result(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    p_result_t
    """
    def __init__(self):
        self.fields = OrderedDict([
            ('result', EnumField(
                size=2,
                enum_type=ContextResult
            )),
            ('reason', EnumField(
                size=2,
                enum_type=ResultReason
            )),
            ('transfer_syntax', StructureField(
                size=20,
                structure_type=SyntaxIdElement
            )),
        ])
        super(Result, self).__init__()


class BindPDU(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagtcjh_28

    The bind PDU
    A BIND PDU message
    rpcconn_bind_hdr_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(
                size=1,
                default=0
            )),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.BIND
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(
                size=2,
                default=lambda s: len(s['auth_verifier'])
            )),
            ('call_id', IntField(size=4)),
            ('max_xmit_frag', IntField(
                size=2,
                default=4280
            )),
            ('max_recv_frag', IntField(
                size=2,
                default=4280
            )),
            ('assoc_group_id', IntField(size=4)),
            # p_context_list_t
            ('n_context_elem', IntField(
                size=1,
                default=lambda s: len(s['context_elems'].get_value())
            )),
            ('reserved', IntField(size=1)),
            ('reserved2', IntField(size=2)),
            ('context_elems', ListField(
                list_count=lambda s: s['n_context_elem'].get_value(),
                list_type=StructureField(structure_type=ContextElement),
                unpack_func=lambda s, d: self._unpack_context_elems(s, d)
            )),
            ('auth_verifier', BytesField(
                size=lambda s: s['auth_length'].get_value()
            ))
        ])
        super(BindPDU, self).__init__()

    def _unpack_context_elems(self, structure, data):
        context_elems = []
        while data != b"":
            context_elem = ContextElement()
            data = context_elem.unpack(data)
            context_elems.append(context_elem)

        return context_elems


class BindAckPDU(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagtcjh_28

    The bind_ack PDU
    A BIND ACK PDU message
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(size=1)),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.BIND_ACK
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(
                size=2,
                default=lambda s: len(s['auth_verifier'])
            )),
            ('call_id', IntField(size=4)),
            ('max_xmit_frag', IntField(size=2)),
            ('max_recv_frag', IntField(size=2)),
            ('assoc_group_id', IntField(size=4)),
            # port_any_t
            ('sec_addr_len', IntField(
                size=2,
                default=lambda s: len(s['sec_addr'])
            )),
            ('sec_addr', BytesField(
                size=lambda s: s['sec_addr_len'].get_value()
            )),
            ('pad2', BytesField(
                size=lambda s: self._pad2_size(s),
                default=lambda s: b"\x00" * self._pad2_size(s)
            )),
            # p_result_list_t
            ('n_results', IntField(
                size=1,
                default=lambda s: len(s['results'].get_value())
            )),
            ('reserved', IntField(size=1)),
            ('reserved2', IntField(size=2)),
            ('results', ListField(
                list_count=lambda s: s['n_results'].get_value(),
                list_type=StructureField(
                    size=24,
                    structure_type=Result
                )
            )),
            ('auth_verifier', BytesField(
                size=lambda s: s['auth_length'].get_value()
            ))
        ])
        super(BindAckPDU, self).__init__()

    def _pad2_size(self, structure):
        sec_addr_size = 2 + len(structure['sec_addr'])

        mod = sec_addr_size % 8
        return 8 - mod if sec_addr_size > 8 else mod


class BindNakPDU(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    rpcconn_bind_nak_hdr_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(size=1)),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.BIND_NAK
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(size=2)),
            ('call_id', IntField(size=4)),
            ('provider_reject_reason', EnumField(
                size=2,
                enum_type=BindNakReason
            )),
            # versions
            ('n_protocols', IntField(
                size=1,
                default=lambda s: len(s['p_protocols'].get_value())
            )),
            ('p_protocols', ListField(
                list_type=IntField(size=2),
                list_count=lambda s: s['n_protocols'].get_value()
            ))
        ])
        super(BindNakPDU, self).__init__()


class FaultPDU(Structure):
    """
    http://pubs.opengroup.org/onlinepubs/9629399/chap12.htm#tagcjh_17_06_03
    rpcconn_fault_hdr_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(size=1)),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.FAULT
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(size=2)),
            ('call_id', IntField(size=4)),
            ('alloc_hint', IntField(size=4)),
            ('p_cont_id', IntField(size=2)),
            ('cancel_count', IntField(size=1)),
            ('reserved', IntField(size=1)),
            ('status', EnumField(
                size=4,
                enum_type=FaultStatus,
                enum_strict=False
            ))
        ])
        super(FaultPDU, self).__init__()


class RequestPDU(Structure):
    """
    rpcconn_request_hdr_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(size=1)),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.REQUEST
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(
                size=2,
                default=lambda s: len(s['auth_verifier'])
            )),
            ('call_id', IntField(size=4)),
            ('alloc_hint', IntField(size=4)),
            ('cont_id', IntField(size=2)),
            ('opnum', IntField(size=2)),
            ('object', BytesField(
                size=lambda s:
                16 if s['pfx_flags'].has_flag(PFlags.PFC_OBJECT_UUID) else 0
            )),
            ('stub_data', BytesField(
                size=lambda s: self._get_stub_data_size(s)
            )),
            ('auth_verifier', BytesField(
                size=lambda s: s['auth_length'].get_value()
            ))
        ])
        super(RequestPDU, self).__init__()

    def _get_stub_data_size(self, structure):
        total_size = structure['frag_length'].get_value()
        fixed_size = 24
        object_size = len(structure['object'])
        auth_size = len(structure['auth_verifier'])

        return total_size - fixed_size - object_size - auth_size


class ResponsePDU(Structure):
    """
    rpcconn_response_hdr_t
    """

    def __init__(self):
        self.fields = OrderedDict([
            ('rpc_vers', IntField(
                size=1,
                default=5
            )),
            ('rpc_vers_minor', IntField(size=1)),
            ('ptype', EnumField(
                size=1,
                enum_type=PType,
                default=PType.RESPONSE
            )),
            ('pfx_flags', FlagField(
                size=1,
                flag_type=PFlags
            )),
            ('packed_drep', StructureField(
                size=4,
                structure_type=DataRepresentationFormat
            )),
            ('frag_length', IntField(
                size=2,
                default=lambda s: len(s)
            )),
            ('auth_length', IntField(
                size=2,
                default=lambda s: len(s['auth_verifier'])
            )),
            ('call_id', IntField(size=4)),
            ('alloc_hint', IntField(size=4)),
            ('cont_id', IntField(size=2)),
            ('cancel_count', IntField(size=1)),
            ('reserved', IntField(size=1)),
            ('stub_data', BytesField(
                size=lambda s: self._get_stub_data_size(s)
            )),
            ('auth_verifier', BytesField(
                size=lambda s: s['auth_length'].get_value()
            ))
        ])
        super(ResponsePDU, self).__init__()

    def _get_stub_data_size(self, structure):
        total_size = structure['frag_length'].get_value()
        fixed_size = 24
        auth_size = structure['auth_length'].get_value()

        return total_size - fixed_size - auth_size
