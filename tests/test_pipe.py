# -*- coding: utf-8 -*-
# Copyright: (c) 2019, Jordan Borean (@jborean93) <jborean93@gmail.com>
# MIT License (see LICENSE or https://opensource.org/licenses/MIT)

from pypsexec.pipe import (
    FSCTLPipeWait,
)


class TestFSCTLPipeWait(object):

    def test_create_message(self):
        message = FSCTLPipeWait()
        message['name'] = "pipe".encode('utf-16-le')
        expected = b"\x00\x00\x00\x00\x00\x00\x00\x00" \
                   b"\x08\x00\x00\x00" \
                   b"\x00" \
                   b"\x00" \
                   b"\x70\x00\x69\x00\x70\x00\x65\x00"
        actual = message.pack()
        assert len(message) == 22
        assert actual == expected

    def test_parse_message(self):
        actual = FSCTLPipeWait()
        data = b"\x00\x00\x00\x00\x00\x00\x00\x00" \
               b"\x08\x00\x00\x00" \
               b"\x00" \
               b"\x00" \
               b"\x70\x00\x69\x00\x70\x00\x65\x00"
        data = actual.unpack(data)
        assert len(actual) == 22
        assert data == b""
        assert actual['timeout'].get_value() == 0
        assert actual['name_length'].get_value() == 8
        assert not actual['timeout_specified'].get_value()
        assert actual['padding'].get_value() == 0
        assert actual['name'].get_value() == "pipe".encode('utf-16-le')
