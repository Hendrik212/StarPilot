#!/usr/bin/env python3
"""
Probe the VW Crafter MK2 EPS for XCP/CCP protocol support.

Tries XCP CONNECT on several candidate CAN ID pairs to see if the EPS responds.
This is non-destructive — CONNECT is a read-only handshake.

PQ flasher used CCP at 0x6D2/0x6D3 (station addr 0x0).
MQB EPS UDS address is 0x712/0x77C on bus 1.
XCP/CCP addresses are often near the UDS addresses or use standard ranges.

Usage:
  sudo kill $(pidof pandad manager) 2>/dev/null
  PYTHONPATH=/data/openpilot:/data/openpilot/opendbc_repo \
    /usr/local/venv/bin/python3 /data/openpilot/selfdrive/debug/eps_xcp_probe.py
"""

import time
import struct
from opendbc.car.structs import CarParams
from panda import Panda

# Candidate XCP/CCP TX/RX address pairs to try
# Format: (tx_addr, rx_addr, description)
CANDIDATES = [
    # PQ flasher CCP addresses
    (0x6D2, 0x6D3, "PQ CCP (0x6D2/0x6D3)"),
    # Common XCP broadcast
    (0x700, 0x701, "XCP broadcast (0x700/0x701)"),
    # Near EPS UDS address
    (0x710, 0x711, "Near EPS UDS (0x710/0x711)"),
    (0x712, 0x77C, "EPS UDS addr as XCP (0x712/0x77C)"),
    # Standard VW XCP ranges
    (0x7E0, 0x7E1, "Standard diag (0x7E0/0x7E1)"),
    # CCP standard addresses
    (0x200, 0x201, "CCP low (0x200/0x201)"),
    (0x201, 0x200, "CCP low reversed (0x201/0x200)"),
    # Broadcast scan: try XCP CONNECT on common offsets from EPS base
    (0x600, 0x601, "XCP (0x600/0x601)"),
    (0x601, 0x600, "XCP reversed (0x601/0x600)"),
    (0x6D0, 0x6D1, "Near PQ CCP (0x6D0/0x6D1)"),
    (0x6D3, 0x6D2, "PQ CCP reversed (0x6D3/0x6D2)"),
]

# XCP CONNECT command (mode=0x00 normal)
XCP_CONNECT = bytes([0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

# CCP CONNECT command (cmd=0x01, counter=0x00, station_addr=0x0000)
CCP_CONNECT = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])


def probe_address(panda, tx_addr, rx_addr, bus, payload, protocol, timeout=0.5):
    """Send a CONNECT and listen for any response."""
    panda.can_clear(bus)
    panda.can_clear(0xFFFF)
    panda.can_send(tx_addr, payload, bus)

    start = time.time()
    while time.time() - start < timeout:
        msgs = panda.can_recv() or []
        for addr, data, msg_bus in msgs:
            if msg_bus == bus and addr == rx_addr:
                return bytes(data)
            # Also check for any response on any address (ECU might respond on unexpected addr)
            if msg_bus == bus and addr != tx_addr and len(data) > 0:
                data = bytes(data)
                # XCP positive response starts with 0xFF, CCP positive response starts with 0xFF
                if data[0] == 0xFF:
                    return data
        time.sleep(0.001)
    return None


def main():
    print("=== VW Crafter MK2 EPS — XCP/CCP Protocol Probe ===\n")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    bus = 1 if panda.has_obd() else 0
    print(f"Panda connected, bus={bus}\n")

    print("--- Probing XCP CONNECT ---\n")
    for tx, rx, desc in CANDIDATES:
        resp = probe_address(panda, tx, rx, bus, XCP_CONNECT, "XCP")
        if resp:
            print(f"  [HIT] {desc}: TX=0x{tx:03x} RX=0x{rx:03x} -> {resp.hex()}")
        else:
            print(f"  [---] {desc}: TX=0x{tx:03x} RX=0x{rx:03x} -> no response")

    print("\n--- Probing CCP CONNECT ---\n")
    for tx, rx, desc in CANDIDATES:
        resp = probe_address(panda, tx, rx, bus, CCP_CONNECT, "CCP")
        if resp:
            print(f"  [HIT] {desc}: TX=0x{tx:03x} RX=0x{rx:03x} -> {resp.hex()}")
        else:
            print(f"  [---] {desc}: TX=0x{tx:03x} RX=0x{rx:03x} -> no response")

    # Also do a wider scan: send XCP CONNECT on every address from 0x600-0x7FF
    # and listen for ANY response
    print("\n--- Wide scan: XCP CONNECT on 0x600-0x7FF, listening on all ---\n")
    hits = []
    for tx in range(0x600, 0x800):
        panda.can_clear(bus)
        panda.can_clear(0xFFFF)
        panda.can_send(tx, XCP_CONNECT, bus)
        time.sleep(0.01)  # small delay between probes
        msgs = panda.can_recv() or []
        for addr, data, msg_bus in msgs:
            if msg_bus == bus and addr != tx:
                data = bytes(data)
                hits.append((tx, addr, data))
                print(f"  [HIT] TX=0x{tx:03x} -> response on 0x{addr:03x}: {data.hex()}")

    if not hits:
        print("  No responses in wide scan.")

    # Same for CCP
    print("\n--- Wide scan: CCP CONNECT on 0x600-0x7FF, listening on all ---\n")
    hits2 = []
    for tx in range(0x600, 0x800):
        panda.can_clear(bus)
        panda.can_clear(0xFFFF)
        panda.can_send(tx, CCP_CONNECT, bus)
        time.sleep(0.01)
        msgs = panda.can_recv() or []
        for addr, data, msg_bus in msgs:
            if msg_bus == bus and addr != tx:
                data = bytes(data)
                hits2.append((tx, addr, data))
                print(f"  [HIT] TX=0x{tx:03x} -> response on 0x{addr:03x}: {data.hex()}")

    if not hits2:
        print("  No responses in wide scan.")

    print(f"\n=== Done. Total XCP hits: {len(hits)}, CCP hits: {len(hits2)} ===")


if __name__ == "__main__":
    main()
