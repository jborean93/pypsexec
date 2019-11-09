# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

import pytest
import uuid

from pypsexec.exceptions import (
    PDUException,
)

from pypsexec.rpc import (
    BindAckPDU,
    BindNakPDU,
    BindNakReason,
    BindPDU,
    ContextElement,
    ContextResult,
    DataRepresentationFormat,
    FaultPDU,
    FaultStatus,
    FloatingPointRepresentation,
    IntegerCharacterRepresentation,
    PFlags,
    PType,
    RequestPDU,
    ResponsePDU,
    Result,
    ResultReason,
    SyntaxIdElement,
    parse_pdu,
)


def test_parse_pdu_known():
    message = BindNakPDU()
    message['packed_drep'] = DataRepresentationFormat()
    message['call_id'] = 4
    message['provider_reject_reason'] = BindNakReason.LOCAL_LIMIT_EXCEEDED
    message['p_protocols'] = [5]
    data = message.pack()
    actual = parse_pdu(data)
    assert isinstance(actual, BindNakPDU)
    assert len(actual) == 21


def test_parse_pdu_unknown():
    data = b"\x00\x00\x99"
    with pytest.raises(PDUException) as exc:
        parse_pdu(data)
    assert str(exc.value) == "Cannot parse PDU of type 153"


class TestDataRepresentationFormat(object):

    def test_create_message(self):
        message = DataRepresentationFormat()
        message['floating_point'] = FloatingPointRepresentation.IEEE
        expected = b"\x10" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00"
        actual = message.pack()
        assert len(message) == 4
        assert actual == expected

    def test_parse_message(self):
        actual = DataRepresentationFormat()
        data = b"\x10" \
               b"\x00" \
               b"\x00" \
               b"\x00"
        data = actual.unpack(data)
        assert len(actual) == 4
        assert data == b""
        assert actual['integer_character'].get_value() == \
            IntegerCharacterRepresentation.ASCII_LITTLE_ENDIAN
        assert actual['floating_point'].get_value() == \
            FloatingPointRepresentation.IEEE
        assert actual['reserved1'].get_value() == 0
        assert actual['reserved2'].get_value() == 0


class TestSyntaxIdElement(object):

    def test_create_message(self):
        message = SyntaxIdElement()
        message['uuid'] = uuid.UUID(bytes=b"\xff" * 16)
        message['version'] = 2
        expected = b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x02\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 20
        assert actual == expected

    def test_parse_message(self):
        actual = SyntaxIdElement()
        data = b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x02\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 20
        assert data == b""
        assert actual['uuid'].get_value() == uuid.UUID(bytes=b"\xff" * 16)
        assert actual['version'].get_value() == 2


class TestContextElement(object):

    def test_create_message(self):
        message = ContextElement()
        message['context_id'] = 4
        syntax1 = SyntaxIdElement()
        syntax1['uuid'] = uuid.UUID(bytes=b"\xff" * 16)
        syntax2 = SyntaxIdElement()
        syntax2['uuid'] = uuid.UUID(bytes=b"\xee" * 16)
        syntax3 = SyntaxIdElement()
        syntax3['uuid'] = uuid.UUID(bytes=b"\xdd" * 16)
        message['abstract_syntax'] = syntax1
        message['transfer_syntaxes'] = [syntax2, syntax3]
        expected = b"\x04\x00" \
                   b"\x02" \
                   b"\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\xee\xee\xee\xee\xee\xee\xee\xee" \
                   b"\xee\xee\xee\xee\xee\xee\xee\xee" \
                   b"\x00\x00\x00\x00" \
                   b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
                   b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 64
        assert actual == expected

    def test_parse_message(self):
        actual = ContextElement()
        data = b"\x04\x00" \
               b"\x02" \
               b"\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\xee\xee\xee\xee\xee\xee\xee\xee" \
               b"\xee\xee\xee\xee\xee\xee\xee\xee" \
               b"\x00\x00\x00\x00" \
               b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
               b"\xdd\xdd\xdd\xdd\xdd\xdd\xdd\xdd" \
               b"\x00\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 64
        assert data == b""
        assert actual['context_id'].get_value() == 4
        assert actual['n_transfer_syn'].get_value() == 2
        assert actual['reserved'].get_value() == 0
        assert isinstance(actual['abstract_syntax'].get_value(),
                          SyntaxIdElement)
        assert actual['abstract_syntax']['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert actual['abstract_syntax']['version'].get_value() == 0
        transfer_syntaxes = actual['transfer_syntaxes'].get_value()
        assert len(transfer_syntaxes) == 2
        assert transfer_syntaxes[0]['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xee" * 16)
        assert transfer_syntaxes[0]['version'].get_value() == 0
        assert transfer_syntaxes[1]['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xdd" * 16)
        assert transfer_syntaxes[1]['version'].get_value() == 0


class TestResult(object):

    def test_create_message(self):
        message = Result()
        message['result'] = ContextResult.ACCEPTANCE
        message['reason'] = ResultReason.REASON_NOT_SPECIFIED
        syntax = SyntaxIdElement()
        syntax['uuid'] = uuid.UUID(bytes=b"\xff" * 16)
        syntax['version'] = 2
        message['transfer_syntax'] = syntax
        expected = b"\x00\x00" \
                   b"\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x02\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 24
        assert actual == expected

    def test_parse_message(self):
        actual = Result()
        data = b"\x00\x00" \
               b"\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x02\x00\x00\x00"
        data = actual.unpack(data)
        assert len(actual) == 24
        assert data == b""
        assert actual['result'].get_value() == ContextResult.ACCEPTANCE
        assert actual['reason'].get_value() == \
            ResultReason.REASON_NOT_SPECIFIED
        assert actual['transfer_syntax']['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert actual['transfer_syntax']['version'].get_value() == 2


class TestBindPDU(object):

    def test_create_message(self):
        message = BindPDU()
        message['pfx_flags'].set_flag(PFlags.PFC_MAYBE)
        packed_drep = DataRepresentationFormat()
        packed_drep['integer_character'] = \
            IntegerCharacterRepresentation.ASCII_LITTLE_ENDIAN
        packed_drep['floating_point'] = FloatingPointRepresentation.IEEE
        message['packed_drep'] = packed_drep
        message['call_id'] = 4
        message['assoc_group_id'] = 2
        con_elem = ContextElement()
        con_elem['context_id'] = 1
        syntax = SyntaxIdElement()
        syntax['uuid'] = uuid.UUID(bytes=b"\xff" * 16)
        con_elem['abstract_syntax'] = syntax
        con_elem['transfer_syntaxes'] = [syntax]
        message['context_elems'] = [con_elem]
        expected = b"\x05" \
                   b"\x00" \
                   b"\x0b" \
                   b"\x40" \
                   b"\x10" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x48\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\xb8\x10" \
                   b"\xb8\x10" \
                   b"\x02\x00\x00\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\x00\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x00\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 72
        assert actual == expected

    def test_parse_message(self):
        actual = BindPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x0b" \
               b"\x40" \
               b"\x10" \
               b"\x00" \
               b"\x00" \
               b"\x00" \
               b"\x48\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\xb8\x10" \
               b"\xb8\x10" \
               b"\x02\x00\x00\x00" \
               b"\x01" \
               b"\x00" \
               b"\x00\x00" \
               b"\x01" \
               b"\x00" \
               b"\x01" \
               b"\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x00\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 72
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.BIND
        assert actual['pfx_flags'].get_value() == PFlags.PFC_MAYBE
        assert actual['packed_drep']['integer_character'].get_value() == \
            IntegerCharacterRepresentation.ASCII_LITTLE_ENDIAN
        assert actual['packed_drep']['floating_point'].get_value() == \
            FloatingPointRepresentation.IEEE
        assert actual['packed_drep']['reserved1'].get_value() == 0
        assert actual['packed_drep']['reserved2'].get_value() == 0
        assert actual['frag_length'].get_value() == 72
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['max_xmit_frag'].get_value() == 4280
        assert actual['max_recv_frag'].get_value() == 4280
        assert actual['assoc_group_id'].get_value() == 2
        assert actual['n_context_elem'].get_value() == 1
        assert actual['reserved'].get_value() == 0
        assert actual['reserved2'].get_value() == 0
        context_elems = actual['context_elems'].get_value()
        assert len(context_elems) == 1
        assert context_elems[0]['context_id'].get_value() == 1
        assert context_elems[0]['n_transfer_syn'].get_value() == 1
        assert context_elems[0]['reserved'].get_value() == 0
        assert context_elems[0]['abstract_syntax']['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert context_elems[0]['abstract_syntax']['version'].get_value() == 0
        transfer_syntaxes = context_elems[0]['transfer_syntaxes'].get_value()
        assert len(transfer_syntaxes) == 1
        assert transfer_syntaxes[0]['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert transfer_syntaxes[0]['version'].get_value() == 0
        assert actual['auth_verifier'].get_value() == b""


class TestBindAckPDU(object):

    def test_create_message(self):
        message = BindAckPDU()
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 4
        message['max_xmit_frag'] = 4280
        message['max_recv_frag'] = 4280
        message['assoc_group_id'] = 2
        message['sec_addr'] = b"\x5C\x70\x69\x70\x65\x5C\x6E\x74" \
                              b"\x73\x76\x63\x73\x00"

        syntax = SyntaxIdElement()
        syntax['uuid'] = uuid.UUID(bytes=b"\xff" * 16)
        syntax['version'] = 2
        res1 = Result()
        res1['result'] = ContextResult.ACCEPTANCE
        res1['reason'] = ResultReason.REASON_NOT_SPECIFIED
        res1['transfer_syntax'] = syntax
        res2 = Result()
        res2['result'] = ContextResult.NEGOTIATE_ACK
        res2['reason'] = ResultReason.LOCAL_LIMIT_EXCEEDED
        res2['transfer_syntax'] = syntax
        message['results'] = [res1, res2]
        expected = b"\x05" \
                   b"\x00" \
                   b"\x0c" \
                   b"\x00" \
                   b"\x10\x00\x00\x00" \
                   b"\x5c\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\xb8\x10" \
                   b"\xb8\x10" \
                   b"\x02\x00\x00\x00" \
                   b"\x0d\x00" \
                   b"\x5c\x70\x69\x70\x65\x5C\x6e\x74" \
                   b"\x73\x76\x63\x73\x00" \
                   b"\x00" \
                   b"\x02" \
                   b"\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\x00\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x02\x00\x00\x00" \
                   b"\x03\x00" \
                   b"\x03\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x02\x00\x00\x00"
        actual = message.pack()
        assert len(message) == 92
        assert actual == expected

    def test_parse_message(self):
        actual = BindAckPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x0c" \
               b"\x00" \
               b"\x10\x00\x00\x00" \
               b"\x5c\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\xb8\x10" \
               b"\xb8\x10" \
               b"\x02\x00\x00\x00" \
               b"\x0d\x00" \
               b"\x5c\x70\x69\x70\x65\x5C\x6e\x74" \
               b"\x73\x76\x63\x73\x00" \
               b"\x00" \
               b"\x02" \
               b"\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\x00\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x02\x00\x00\x00" \
               b"\x03\x00" \
               b"\x03\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x02\x00\x00\x00"
        actual.unpack(data)
        assert len(actual) == 92
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == 12
        assert actual['pfx_flags'].get_value() == 0
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 92
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['max_xmit_frag'].get_value() == 4280
        assert actual['max_recv_frag'].get_value() == 4280
        assert actual['assoc_group_id'].get_value() == 2
        assert actual['sec_addr_len'].get_value() == 13
        assert actual['sec_addr'].get_value() == \
            b"\x5c\x70\x69\x70\x65\x5C\x6e\x74" \
            b"\x73\x76\x63\x73\x00"
        assert actual['pad2'].get_value() == b"\x00"
        assert actual['n_results'].get_value() == 2
        assert actual['reserved'].get_value() == 0
        assert actual['reserved2'].get_value() == 0
        results = actual['results'].get_value()
        assert len(results) == 2
        assert results[0]['result'].get_value() == ContextResult.ACCEPTANCE
        assert results[0]['reason'].get_value() == \
            ResultReason.REASON_NOT_SPECIFIED
        assert results[0]['transfer_syntax']['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert results[0]['transfer_syntax']['version'].get_value() == 2
        assert results[1]['result'].get_value() == ContextResult.NEGOTIATE_ACK
        assert results[1]['reason'].get_value() == \
            ResultReason.LOCAL_LIMIT_EXCEEDED
        assert results[1]['transfer_syntax']['uuid'].get_value() == \
            uuid.UUID(bytes=b"\xff" * 16)
        assert results[1]['transfer_syntax']['version'].get_value() == 2
        assert actual['auth_verifier'].get_value() == b""


class TestBindNakPDU(object):

    def test_create_message(self):
        message = BindNakPDU()
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 4
        message['provider_reject_reason'] = BindNakReason.LOCAL_LIMIT_EXCEEDED
        message['p_protocols'] = [5]
        expected = b"\x05" \
                   b"\x00" \
                   b"\x0d" \
                   b"\x00" \
                   b"\x10\x00\x00\x00" \
                   b"\x15\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x02\x00" \
                   b"\x01" \
                   b"\x05\x00"
        actual = message.pack()
        assert len(actual) == 21
        assert actual == expected

    def test_parse_message(self):
        actual = BindNakPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x0d" \
               b"\x00" \
               b"\x10\x00\x00\x00" \
               b"\x15\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x02\x00" \
               b"\x01" \
               b"\x05\x00"
        data = actual.unpack(data)
        assert len(actual) == 21
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.BIND_NAK
        assert actual['pfx_flags'].get_value() == 0
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 21
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['provider_reject_reason'].get_value() == \
            BindNakReason.LOCAL_LIMIT_EXCEEDED
        assert actual['n_protocols'].get_value() == 1
        assert len(actual['p_protocols'].get_value()) == 1
        assert actual['p_protocols'][0] == 5


class TestFaultPDU(object):

    def test_create_message(self):
        message = FaultPDU()
        message['pfx_flags'].set_flag(PFlags.PFC_DID_NOT_EXECUTE)
        message['pfx_flags'].set_flag(PFlags.PFC_LAST_FRAG)
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 1
        message['alloc_hint'] = 32
        message['status'] = FaultStatus.NCA_S_FAULT_ADDR_ERROR
        expected = b"\x05" \
                   b"\x00" \
                   b"\x03" \
                   b"\x22" \
                   b"\x10\x00\x00\x00" \
                   b"\x1c\x00" \
                   b"\x00\x00" \
                   b"\x01\x00\x00\x00" \
                   b"\x20\x00\x00\x00" \
                   b"\x00\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x02\x00\x00\x1c"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = FaultPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x03" \
               b"\x22" \
               b"\x10\x00\x00\x00" \
               b"\x1c\x00" \
               b"\x00\x00" \
               b"\x01\x00\x00\x00" \
               b"\x20\x00\x00\x00" \
               b"\x00\x00" \
               b"\x00" \
               b"\x00" \
               b"\x02\x00\x00\x1c"
        data = actual.unpack(data)
        assert len(actual) == 28
        assert data == b""
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.FAULT
        assert actual['pfx_flags'].get_value() == 34
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 28
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 1
        assert actual['alloc_hint'].get_value() == 32
        assert actual['p_cont_id'].get_value() == 0
        assert actual['cancel_count'].get_value() == 0
        assert actual['reserved'].get_value() == 0
        assert actual['status'].get_value() == \
            FaultStatus.NCA_S_FAULT_ADDR_ERROR


class TestRequestPDU(object):

    def test_create_message(self):
        message = RequestPDU()
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 4
        message['cont_id'] = 1
        message['opnum'] = 10
        message['stub_data'] = b"\x01\x02\x03\x04"
        expected = b"\x05" \
                   b"\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x10\x00\x00\x00" \
                   b"\x1c\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x0a\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_create_message_with_object(self):
        message = RequestPDU()
        message['pfx_flags'].set_flag(PFlags.PFC_OBJECT_UUID)
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 4
        message['cont_id'] = 1
        message['opnum'] = 10
        message['object'] = b"\xff" * 16
        message['stub_data'] = b"\x01\x02\x03\x04"
        expected = b"\x05" \
                   b"\x00" \
                   b"\x00" \
                   b"\x80" \
                   b"\x10\x00\x00\x00" \
                   b"\x2c\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x00\x00\x00\x00" \
                   b"\x01\x00" \
                   b"\x0a\x00" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\xff\xff\xff\xff\xff\xff\xff\xff" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 44
        assert actual == expected

    def test_parse_message(self):
        actual = RequestPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x00" \
               b"\x00" \
               b"\x10\x00\x00\x00" \
               b"\x1c\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00" \
               b"\x0a\x00" \
               b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 28
        assert data == b""
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.REQUEST
        assert actual['pfx_flags'].get_value() == 0
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 28
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['alloc_hint'].get_value() == 0
        assert actual['cont_id'].get_value() == 1
        assert actual['opnum'].get_value() == 10
        assert actual['object'].get_value() == b""
        assert actual['stub_data'].get_value() == b"\x01\x02\x03\x04"
        assert actual['auth_verifier'].get_value() == b""

    def test_parse_message_with_object(self):
        actual = RequestPDU()
        data = b"\x05" \
               b"\x00" \
               b"\x00" \
               b"\x80" \
               b"\x10\x00\x00\x00" \
               b"\x2c\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x00\x00\x00\x00" \
               b"\x01\x00" \
               b"\x0a\x00" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\xff\xff\xff\xff\xff\xff\xff\xff" \
               b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 44
        assert data == b""
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.REQUEST
        assert actual['pfx_flags'].get_value() == 128
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 44
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['alloc_hint'].get_value() == 0
        assert actual['cont_id'].get_value() == 1
        assert actual['opnum'].get_value() == 10
        assert actual['object'].get_value() == b"\xff" * 16
        assert actual['stub_data'].get_value() == b"\x01\x02\x03\x04"
        assert actual['auth_verifier'].get_value() == b""


class TestResponsePDU(object):

    def test_create_message(self):
        message = ResponsePDU()
        message['packed_drep'] = DataRepresentationFormat()
        message['call_id'] = 4
        message['alloc_hint'] = 8
        message['cont_id'] = 12
        message['cancel_count'] = 1
        message['stub_data'] = b"\x01\x02\x03\x04"
        expected = b"\x05" \
                   b"\x00" \
                   b"\x02" \
                   b"\x00" \
                   b"\x10\x00\x00\x00" \
                   b"\x1c\x00" \
                   b"\x00\x00" \
                   b"\x04\x00\x00\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x0c\x00" \
                   b"\x01" \
                   b"\x00" \
                   b"\x01\x02\x03\x04"
        actual = message.pack()
        assert len(message) == 28
        assert actual == expected

    def test_parse_message(self):
        actual = ResponsePDU()
        data = b"\x05" \
               b"\x00" \
               b"\x02" \
               b"\x00" \
               b"\x10\x00\x00\x00" \
               b"\x1c\x00" \
               b"\x00\x00" \
               b"\x04\x00\x00\x00" \
               b"\x08\x00\x00\x00" \
               b"\x0c\x00" \
               b"\x01" \
               b"\x00" \
               b"\x01\x02\x03\x04"
        data = actual.unpack(data)
        assert len(actual) == 28
        assert data == b""
        assert actual['rpc_vers'].get_value() == 5
        assert actual['rpc_vers_minor'].get_value() == 0
        assert actual['ptype'].get_value() == PType.RESPONSE
        assert actual['pfx_flags'].get_value() == 0
        assert actual['packed_drep'].pack() == b"\x10\x00\x00\x00"
        assert actual['frag_length'].get_value() == 28
        assert actual['auth_length'].get_value() == 0
        assert actual['call_id'].get_value() == 4
        assert actual['alloc_hint'].get_value() == 8
        assert actual['cont_id'].get_value() == 12
        assert actual['cancel_count'].get_value() == 1
        assert actual['reserved'].get_value() == 0
        assert actual['stub_data'].get_value() == b"\x01\x02\x03\x04"
        assert actual['auth_verifier'].get_value() == b""
