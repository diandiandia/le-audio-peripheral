#!/usr/bin/env python3
"""Register a fake MediaEndpoint on BlueZ to trigger BAP ASE configuration.

BlueZ BAP needs a media endpoint to provide codec configuration before
it will write Codec Config / QoS Config / Enable to the remote ASE
Control Point. This script registers a minimal endpoint that accepts
any LC3 configuration, causing BlueZ to push the ASE state machine
through to ENABLING → iso_do_big_sync → append_setup.
"""
import sys
import dbus
import dbus.service
import dbus.mainloop.glib
from gi.repository import GLib

# ── Config ──────────────────────────────────────────────────────────────────
ENDPOINT_PATH = "/test/bap_endpoint"
DEVICE_PATH = "/org/bluez/hci0/dev_DC_A6_32_DC_4A_A4"
ADAPTER_PATH = "/org/bluez/hci0"
# Audio Sink UUID
SINK_UUID = "0000110b-0000-1000-8000-00805f9b34fb"


class BapEndpoint(dbus.service.Object):
    """Minimal MediaEndpoint1 implementation."""

    def __init__(self, bus, path):
        dbus.service.Object.__init__(self, bus, path)

    @dbus.service.method(
        "org.bluez.MediaEndpoint1",
        in_signature="oa{sv}", out_signature=""
    )
    def SetConfiguration(self, transport, properties):
        print(f"[+] SetConfiguration: transport={transport}")
        for k, v in properties.items():
            print(f"    {k} = {v}")
        return

    @dbus.service.method(
        "org.bluez.MediaEndpoint1",
        in_signature="o", out_signature=""
    )
    def ClearConfiguration(self, transport):
        print(f"[*] ClearConfiguration: {transport}")

    @dbus.service.method(
        "org.bluez.MediaEndpoint1",
        in_signature="ay", out_signature="ay"
    )
    def SelectConfiguration(self, capabilities):
        caps = bytes(capabilities)
        print(f"[+] SelectConfiguration called, caps={caps.hex() if caps else 'empty'}")
        # Return LC3 codec config as byte array
        config = bytes([0x06, 0x00, 0x00])
        print(f"[*] Returning config: {config.hex()}")
        return dbus.ByteArray(config)

    @dbus.service.method(
        "org.bluez.MediaEndpoint1",
        in_signature="", out_signature=""
    )
    def Release(self):
        print("[*] Release called")


def main():
    dbus.mainloop.glib.DBusGMainLoop(set_as_default=True)
    bus = dbus.SystemBus()

    # Create the endpoint D-Bus object
    endpoint = BapEndpoint(bus, ENDPOINT_PATH)

    # Register with BlueZ Media1 interface
    media = dbus.Interface(
        bus.get_object("org.bluez", ADAPTER_PATH),
        "org.bluez.Media1"
    )

    props = dbus.Dictionary({
        "UUID": SINK_UUID,
        "Codec": dbus.Byte(0x06),   # LC3
        "Capabilities": dbus.ByteArray(bytes([
            0x0F, 0x00,   # Sampling Frequencies (8/11/16/22k)
            0x03,          # Frame Durations (7.5ms + 10ms)
            0x03,          # Audio Channel Counts (1 + 2)
            0x1E,          # Min Octets Per Frame (30)
            0x78,          # Max Octets Per Frame (120)
            0x01,          # Max Codec Frames Per SDU
        ])),
        "DelayReporting": dbus.Boolean(False),
        "Device": dbus.ObjectPath(DEVICE_PATH),
    }, signature="sv")

    media.RegisterEndpoint(dbus.ObjectPath(ENDPOINT_PATH), props)
    print(f"[+] Endpoint registered at {ENDPOINT_PATH}")
    print(f"[*] Waiting for BlueZ to trigger BAP ASE configuration...")
    print(f"[*] Press Ctrl+C to stop.")

    loop = GLib.MainLoop()
    try:
        loop.run()
    except KeyboardInterrupt:
        print("\n[*] Stopping.")


if __name__ == "__main__":
    main()
