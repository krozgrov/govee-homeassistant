"""Wi-Fi setup encoding, reply evidence and one-shot credential handling."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from bleak.exc import BleakError
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.govee.api.ble import GoveeBLEDevice
from custom_components.govee.api.ble_packet import build_packet
from custom_components.govee.api.ble_wifi import wifi_frames
from custom_components.govee.const import CONF_ENABLE_H6104_BLE, DOMAIN
from custom_components.govee.models import GoveeDevice


def test_transfer_boundaries_and_utf8_byte_lengths():
    frames = wifi_frames("Tést", "password")
    assert all(len(frame) == 20 for frame in frames)
    for frame in frames:
        checksum = 0
        for value in frame:
            checksum ^= value
        assert checksum == 0
    assert frames[0][:4] == bytes([0xA1, 0x11, 0, 2])
    assert frames[-1] == build_packet([0xA1, 0x11, 0xFF])
    payload = b"".join(frame[3:19] for frame in frames[1:-1])
    assert payload.startswith(b"\x05T\xc3\xa9st\x08password\0\0\0\0")
    assert len(wifi_frames("a" * 32, "b" * 63)) == 9


@pytest.mark.parametrize(
    "ssid,password",
    [
        ("", "password"),
        ("é" * 17, "password"),
        ("ok", "short"),
        ("ok", "x" * 64),
        ("a\0b", "password"),
        ("ok", "pass\0word"),
    ],
)
def test_invalid_credentials(ssid, password):
    with pytest.raises(ValueError):
        wifi_frames(ssid, password)


def test_dynamic_api_blocks_and_open_network():
    for api_type, endpoint in [(1, b"http://app.govee.com"), (2, b"https://device.govee.com")]:
        frames = wifi_frames("Test", "", api_type=api_type, hidden_supported=True)
        payload = b"".join(frame[3:19] for frame in frames[1:-1])
        assert payload.startswith(b"\x04Test\0\0\0\0\0" + len(endpoint).to_bytes(2, "big") + endpoint + b"\0")
    with pytest.raises(ValueError):
        wifi_frames("Test", "password", api_type=3)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "outcome", ["wifi_connected", "wifi_accepted", "wifi_sent", "rejected", "disconnect", "write_error"]
)
@pytest.mark.parametrize("transport", ["uart", "plaintext", "encrypted"])
async def test_transfer_and_result_evidence(outcome, transport):
    device = GoveeBLEDevice(MagicMock(), legacy_uart=transport == "uart")
    client = MagicMock(is_connected=True)
    device._client = client
    client.disconnect = AsyncMock()
    client.start_notify = AsyncMock()
    session = MagicMock()
    session.wrap.side_effect = lambda frame: b"encrypted" + frame
    if transport == "encrypted":
        device._session = session
    writes = []
    real_wait_for = asyncio.wait_for

    async def fast_wait(awaitable, timeout):
        return await real_wait_for(awaitable, 0.001)

    async def write(_uuid, frame, **kwargs):
        if transport == "encrypted":
            assert frame.startswith(b"encrypted")
            frame = frame[len(b"encrypted") :]
        writes.append(frame)
        assert kwargs == {"response": False}
        assert device._lock.locked()
        assert device._idle_disconnect_handle is None
        # Echo every outgoing frame, including the header and closing marker.
        device._on_uart_notification(client, bytearray(frame))
        if frame[:3] == b"\xa1\x11\x01" and outcome == "write_error":
            raise BleakError("secret backend packet")
        if frame[:3] == b"\xa1\x11\xff":
            # Delayed data echoes must not become a status-only rejection.
            for earlier in writes:
                device._on_uart_notification(client, bytearray(earlier))
            if outcome == "wifi_connected":
                device._on_uart_notification(client, bytearray(build_packet([0xEE, 0x11, 0])))
            elif outcome in ("wifi_accepted", "rejected"):
                device._on_uart_notification(
                    client, bytearray(build_packet([0xA1, 0x11, 0 if outcome == "wifi_accepted" else 7]))
                )
            elif outcome == "disconnect":
                client.is_connected = False
                device._on_disconnected(client)

    client.write_gatt_char = AsyncMock(side_effect=write)
    with (
        patch.object(device, "_ensure_connected", AsyncMock(return_value=client)),
        patch("custom_components.govee.api.ble.asyncio.sleep", AsyncMock()),
        patch("custom_components.govee.api.ble.asyncio.wait_for", side_effect=fast_wait),
    ):
        if outcome in ("rejected", "disconnect", "write_error"):
            with pytest.raises(BleakError, match="Wi-Fi setup failed") as error:
                await device.async_provision_wifi("Test", "password")
            assert "secret backend packet" not in str(error.value)
        else:
            assert await device.async_provision_wifi("Test", "password") == outcome
    assert build_packet([0x33, 0x17, 1]) in writes
    if outcome != "disconnect":
        assert writes[-1] == build_packet([0x33, 0x17, 0])
        client.disconnect.assert_awaited_once()
    assert device._wifi_replies == {}
    assert device._wifi_echoes == set()
    if transport == "encrypted":
        assert session.wrap.call_count == len(writes)
    elif transport == "plaintext":
        client.start_notify.assert_awaited_once()
    assert device.readback_diagnostics["recent_status_candidates"] == []
    assert device.readback_diagnostics["recent_status_frames"] == []


@pytest.mark.asyncio
async def test_validation_precedes_connection():
    device = GoveeBLEDevice(MagicMock(), legacy_uart=True)
    with patch.object(device, "_ensure_connected", AsyncMock()) as connect:
        with pytest.raises(ValueError):
            await device.async_provision_wifi("Test", "short")
        connect.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["wifi_connected", "wifi_accepted", "wifi_sent", "failure", "invalid"])
@pytest.mark.parametrize("sku", ["H6104", "H6199", "H1270"])
async def test_options_never_store_credentials(hass, enable_custom_integrations, outcome, caplog, sku):
    hass.config.components.update({"bluetooth_adapters", "network"})
    device = GoveeDevice(device_id="tv", sku=sku, name="TV", device_type="devices.types.light", capabilities=())
    entry = MockConfigEntry(domain=DOMAIN, data={"api_key": "key"}, options={CONF_ENABLE_H6104_BLE: True})
    entry.add_to_hass(hass)
    provision = AsyncMock(return_value=outcome)
    if outcome == "failure":
        provision.side_effect = RuntimeError("private-secret-password")
    entry.runtime_data = SimpleNamespace(devices={"tv": device}, async_provision_wifi=provision)
    before = dict(entry.options)
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert "wifi_setup" in result["menu_options"]
    result = await hass.config_entries.options.async_configure(result["flow_id"], {"next_step_id": "wifi_setup"})
    result = await hass.config_entries.options.async_configure(
        result["flow_id"],
        {
            "device_id": "tv",
            "ssid": "private-network",
            "wifi_password": "short" if outcome == "invalid" else "private-secret-password",
        },
    )
    if outcome in ("failure", "invalid"):
        assert result["type"] is FlowResultType.FORM
        assert result["errors"]["base"] == (
            "wifi_setup_failed" if outcome == "failure" else "wifi_invalid_credentials"
        )
        assert "private-secret-password" not in str(result)
        if outcome == "invalid":
            provision.assert_not_awaited()
    else:
        assert result["type"] is FlowResultType.ABORT
        assert result["reason"] == outcome
    assert dict(entry.options) == before
    assert entry.data == {"api_key": "key"}
    assert "private-secret-password" not in caplog.text
    assert "private-network" not in caplog.text


@pytest.mark.asyncio
@pytest.mark.parametrize("sku,opted_in", [("H6104", False), ("H6072", True)])
async def test_unsupported_profiles_not_offered(hass, enable_custom_integrations, sku, opted_in):
    hass.config.components.update({"bluetooth_adapters", "network"})
    device = GoveeDevice(device_id="tv", sku=sku, name="TV", device_type="devices.types.light", capabilities=())
    entry = MockConfigEntry(domain=DOMAIN, data={}, options={CONF_ENABLE_H6104_BLE: opted_in})
    entry.add_to_hass(hass)
    entry.runtime_data = SimpleNamespace(devices={"tv": device})
    result = await hass.config_entries.options.async_init(entry.entry_id)
    assert result["step_id"] == "general"


@pytest.mark.asyncio
async def test_coordinator_recovery_ignores_cloud_offline_and_never_records_credentials():
    from custom_components.govee.coordinator import GoveeCoordinator

    entry = MagicMock(options={}, data={})
    api = MagicMock()
    coord = GoveeCoordinator(
        hass=MagicMock(), config_entry=entry, api_client=api, iot_credentials=None, poll_interval=60
    )
    device = GoveeDevice(
        device_id="light", sku="H6199", name="Light", device_type="devices.types.light", capabilities=()
    )
    coord._devices = {"light": device}
    ble = MagicMock()
    ble.async_provision_wifi = AsyncMock(return_value="wifi_accepted")
    coord._ble_devices["light"] = ble
    with patch.object(coord._ble_handler, "enroll_from_cache"):
        assert await coord.async_provision_wifi("light", "Test", "password") == "wifi_accepted"
        api.record_local_command.assert_not_called()
        with pytest.raises(ValueError):
            await coord.async_provision_wifi("unknown", "Test", "password")
        coord._ble_devices.clear()
        with pytest.raises(ValueError):
            await coord.async_provision_wifi("light", "Test", "password")
