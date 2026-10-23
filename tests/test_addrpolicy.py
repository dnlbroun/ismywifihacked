import ipaddress

import pytest

from netcheck.addrpolicy import AddressPolicy, RefusalReason, RefusedAddress, ScanTarget

VPS4 = ipaddress.IPv4Address("8.9.10.11")
VPS6 = ipaddress.IPv6Address("2a01:4f8::1")


@pytest.fixture
def policy() -> AddressPolicy:
    return AddressPolicy([VPS4, VPS6])


@pytest.mark.parametrize("raw", ["24.0.1.2", "1.1.1.1", "2001:558::1", "2606:4700::1111"])
def test_public_addresses_allowed(policy: AddressPolicy, raw: str) -> None:
    assert policy.check(raw).ip == ipaddress.ip_address(raw)


@pytest.mark.parametrize(
    "raw",
    [
        "10.0.0.1",
        "172.16.5.4",
        "192.168.1.1",
        "127.0.0.1",
        "169.254.169.254",  # cloud metadata
        "0.0.0.0",
        "224.0.0.1",
        "255.255.255.255",
        "240.0.0.1",
        "192.0.2.1",
        "198.18.0.1",
        "::1",
        "::",
        "fe80::1",
        "fd00::1",
        "ff02::1",
        "2001:db8::1",
        "64:ff9b::a00:1",  # NAT64 wrapping 10.0.0.1
        "2002:a00:1::1",  # 6to4 wrapping 10.0.0.1
        "2001:0:4136:e378::1",  # Teredo
        "::ffff:192.168.1.1",  # IPv4-mapped private
        "::ffff:127.0.0.1",
    ],
)
def test_private_and_reserved_refused(policy: AddressPolicy, raw: str) -> None:
    with pytest.raises(RefusedAddress) as exc:
        policy.check(raw)
    assert exc.value.reason is RefusalReason.NOT_PUBLIC


def test_cgnat_refused_with_specific_reason(policy: AddressPolicy) -> None:
    with pytest.raises(RefusedAddress) as exc:
        policy.check("100.72.1.2")
    assert exc.value.reason is RefusalReason.CGNAT


@pytest.mark.parametrize("raw", ["8.9.10.11", "2a01:4f8::1", "::ffff:8.9.10.11"])
def test_own_vps_refused(policy: AddressPolicy, raw: str) -> None:
    with pytest.raises(RefusedAddress) as exc:
        policy.check(raw)
    assert exc.value.reason is RefusalReason.OWN_ADDRESS


@pytest.mark.parametrize(
    "raw",
    ["", " 1.1.1.1", "1.1.1.1 ", "example.com", "1.1.1", "01.1.1.1", "fe80::1%eth0", "1.1.1.1/32"],
)
def test_invalid_refused(policy: AddressPolicy, raw: str) -> None:
    with pytest.raises(RefusedAddress) as exc:
        policy.check(raw)
    assert exc.value.reason is RefusalReason.INVALID


def test_ipv4_mapped_public_is_unwrapped(policy: AddressPolicy) -> None:
    assert policy.check("::ffff:1.1.1.1").ip == ipaddress.IPv4Address("1.1.1.1")


def test_loopback_refused_by_default_and_only_loopback_unlocked() -> None:
    assert not AddressPolicy([]).is_allowed("127.0.0.1")
    test_policy = AddressPolicy([], allow_loopback=True)
    assert test_policy.check("127.0.0.1").ip.is_loopback
    assert test_policy.check("::1").ip.is_loopback
    # The test switch must not open up anything else.
    assert not test_policy.is_allowed("10.0.0.1")
    assert not test_policy.is_allowed("169.254.169.254")


def test_scan_target_cannot_be_forged() -> None:
    with pytest.raises(TypeError):
        ScanTarget(ipaddress.IPv4Address("10.0.0.1"), object())
