"""Shared experimental Govee Wi-Fi provisioning frames; never log these payloads.

References: damient/govee-toolkit@ceef296f6382881c5f07698d78fb5719ebca6686
docs/protocol/ble.md section 4, and
Brady-Woods/govee-ble-local spec/docs/GOVEE_BLE_GATT_PROTOCOL.md (H6104 UART,
MULTI_WIFI and WifiNotifyParse). Provisioning still needs per-model field testing.
"""

from .ble_packet import build_packet

# Protocol candidates, not a claim that provisioning has passed hardware tests.
# Wi-Fi capability is separate from the control-command allowlist.
WIFI_SETUP_MODELS = frozenset({"H6199", "H1270"})


def supports_wifi_setup(sku: str, *, experimental_h6104: bool = False) -> bool:
    """Return whether this SKU has a provisioning transport profile."""
    return sku in WIFI_SETUP_MODELS or (sku == "H6104" and experimental_h6104)


def wifi_frames(ssid: str, password: str, *, api_type: int = 0, hidden_supported: bool = False) -> list[bytes]:
    """Build the A1/11 transfer for a visible network, using UTC offset zero.

    Length limits count encoded bytes, not characters. Validate before any BLE
    write. Empty passwords explicitly select an open network. The offset and
    production fields follow the documented layout; negative offsets are not
    established, so this experimental setup uses UTC.
    """
    network, secret = ssid.encode("utf-8"), password.encode("utf-8")
    if not 1 <= len(network) <= 32 or b"\0" in network:
        raise ValueError("Wi-Fi name must be 1 to 32 UTF-8 bytes without NUL")
    if b"\0" in secret or (secret and not 8 <= len(secret) <= 63):
        raise ValueError("Wi-Fi password must be empty or 8 to 63 UTF-8 bytes without NUL")
    if api_type not in (0, 1, 2):
        raise ValueError("Unsupported Wi-Fi API type")
    payload = bytes([len(network)]) + network + bytes([len(secret)]) + secret + bytes(4)
    if api_type:
        endpoint = b"http://app.govee.com" if api_type == 1 else b"https://device.govee.com"
        payload += len(endpoint).to_bytes(2, "big") + endpoint
    elif hidden_supported:
        payload += bytes(2)
    if hidden_supported:
        payload += b"\0"  # visible network
    chunks = [payload[index : index + 16] for index in range(0, len(payload), 16)]
    return [
        build_packet([0xA1, 0x11, 0, len(chunks)]),
        *(build_packet([0xA1, 0x11, index, *chunk]) for index, chunk in enumerate(chunks, 1)),
        build_packet([0xA1, 0x11, 0xFF]),
    ]
