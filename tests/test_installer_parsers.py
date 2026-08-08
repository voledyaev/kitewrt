import pytest
from installer.parsers import goarch_from_uname, is_openwrt

# --- goarch_from_uname -----------------------------------------------------


def test_goarch_aarch64():
    assert goarch_from_uname("aarch64") == "arm64"


def test_goarch_x86_64_with_newline():
    assert goarch_from_uname("x86_64\n") == "amd64"


def test_goarch_armv7():
    assert goarch_from_uname("armv7l") == "armv7"


def test_goarch_unknown_raises():
    with pytest.raises(ValueError):
        goarch_from_uname("sparc64")


# --- is_openwrt ------------------------------------------------------------


def test_is_openwrt_os_release():
    assert is_openwrt('NAME="OpenWrt"\nID=openwrt\nVERSION_ID="21.02.0"\n')


def test_is_openwrt_glinet():
    # GL.iNet firmware reports OpenWrt in os-release.
    assert is_openwrt('NAME="OpenWrt"\nVERSION="21.02-SNAPSHOT"\nPRETTY_NAME="GL.iNet"\n')


def test_is_openwrt_false_on_other_distro():
    assert not is_openwrt('NAME="Ubuntu"\nID=ubuntu\n')
