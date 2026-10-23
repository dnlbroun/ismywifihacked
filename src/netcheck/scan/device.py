"""Parse a UPnP device description, keeping only whitelisted fields."""

from __future__ import annotations

from xml.etree.ElementTree import Element

import defusedxml.ElementTree as SafeET
from defusedxml import DefusedXmlException

from netcheck.scan.models import DeviceInfo, clean_text

_FIRMWARE_TAGS = ("firmwareVersion", "softwareVersion", "swVersion", "firmware")


class DeviceParseError(Exception):
    pass


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _child_text(parent: Element, name: str) -> str | None:
    for child in parent:
        if _local(child.tag) == name:
            return clean_text(child.text)
    return None


def parse_device_description(body: bytes) -> DeviceInfo:
    try:
        # forbid_dtd also blocks external entities and entity-expansion bombs.
        root = SafeET.fromstring(body, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except (DefusedXmlException, SafeET.ParseError, ValueError) as exc:
        raise DeviceParseError(type(exc).__name__) from None

    # The root device only: <root><device>...</device></root>.
    device = next((el for el in root if _local(el.tag) == "device"), None)
    if device is None:
        raise DeviceParseError("no device element")

    name = _child_text(device, "modelName")
    number = _child_text(device, "modelNumber")
    model = clean_text(" ".join(x for x in (name, number) if x)) if (name or number) else None
    firmware = next((v for t in _FIRMWARE_TAGS if (v := _child_text(device, t))), None)
    return DeviceInfo(
        manufacturer=_child_text(device, "manufacturer"),
        model=model,
        firmware=firmware,
    )
