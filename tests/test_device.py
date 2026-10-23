import pytest

from netcheck.scan.device import DeviceParseError, parse_device_description
from netcheck.scan.models import clean_text
from tests.netfixtures import DEVICE_XML


def test_whitelisted_fields_only() -> None:
    d = parse_device_description(DEVICE_XML)
    assert d.manufacturer == "ACME Networks"
    assert d.model == "WR-1000 v2"
    assert d.firmware == "1.2.3"
    # Nothing else (serial, UDN, friendly name) is even representable.
    assert set(vars(d)) == {"manufacturer", "model", "firmware"}


def test_no_namespace_and_missing_fields() -> None:
    d = parse_device_description(b"<root><device><modelName>X</modelName></device></root>")
    assert (d.manufacturer, d.model, d.firmware) == (None, "X", None)


def test_fields_truncated_and_control_chars_stripped() -> None:
    xml = (
        "<root><device><manufacturer>"
        + "AB\u200e\u202e" * 100
        + "</manufacturer><modelName>line1\nline2\ttab</modelName></device></root>"
    ).encode()
    d = parse_device_description(xml)
    assert d.manufacturer is not None
    assert len(d.manufacturer) == 128
    assert d.manufacturer == "AB" * 64
    assert d.model == "line1 line2 tab"


def test_markup_kept_as_plain_text() -> None:
    # Escaping is the template's job; the parser just hands back the string.
    xml = (
        b"<root><device><manufacturer>&lt;script&gt;alert(1)&lt;/script&gt;"
        b"</manufacturer></device></root>"
    )
    assert parse_device_description(xml).manufacturer == "<script>alert(1)</script>"


@pytest.mark.parametrize(
    "xml",
    [
        # XXE: external entity
        b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<root><device><manufacturer>&x;</manufacturer></device></root>",
        # XXE: parameter entity / external DTD
        b'<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://127.0.0.1:1/evil.dtd">'
        b"<root><device/></root>",
        # billion laughs
        b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
        b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
        b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">]>'
        b"<root><device><manufacturer>&lol3;</manufacturer></device></root>",
        b"not xml",
        b"",
        b"<root><nodevice/></root>",
    ],
)
def test_hostile_or_broken_xml_rejected(xml: bytes) -> None:
    with pytest.raises(DeviceParseError):
        parse_device_description(xml)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        (None, None),
        ("", None),
        ("   ", None),
        (b"\xff\xfeok", "��ok"),
        ("a\x00b​c", "abc"),
        ("x" * 500, "x" * 128),
    ],
)
def test_clean_text(raw: str | bytes | None, expected: str | None) -> None:
    assert clean_text(raw) == expected
