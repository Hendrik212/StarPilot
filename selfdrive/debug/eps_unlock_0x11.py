#!/usr/bin/env python3
"""
VW MQB ZFLS EPS — Level 0x11 (programming) security access test.

Tests whether the SA2 script from FL_5Q0909144AA_H2_1081.odx works
on the Crafter MK2 EPS (2N0909144J / EV_SteerAssisMNB).

SA2 bytecode: 680587003F173593A3FF78904A0182494C
  FOR(5) XOR(0x003F1735) ADD(0xA3FF7890) BCC(1) RSR NXT DON

Usage:
  Stop openpilot first:  sudo kill $(pgrep -f 'pandad|manager')
  Run:  /usr/local/venv/bin/python3 selfdrive/debug/eps_unlock_0x11.py
"""

import struct
import sys
from opendbc.car.uds import UdsClient, MessageTimeoutError, NegativeResponseError, SESSION_TYPE
from opendbc.car.structs import CarParams
from panda import Panda

MQB_EPS_CAN_ADDR = 0x712
RX_OFFSET = 0x6a

# UDS security access sub-functions for level 0x11
SA_REQUEST_SEED = 0x11  # odd = request seed
SA_SEND_KEY = 0x12      # even = send key


def compute_key_level_0x11(seed: int) -> int:
    """Compute level 0x11 key for VW Crafter MK2 ZFLS EPS (2N0909144J).

    Captured from ODIS sniff: key = seed (identity function).
    """
    return seed & 0xFFFFFFFF


def main():
    print("=== VW MQB ZFLS EPS — Level 0x11 Security Access Test ===\n")

    # Connect to panda
    print("[1/5] Connecting to panda...")
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:
        print(f"  FAILED: {e}")
        print("  Is openpilot stopped? Run: sudo kill $(pgrep -f 'pandad|manager')")
        sys.exit(1)
    bus = 1 if panda.has_obd() else 0
    print(f"  OK — bus={bus}")

    # Create UDS client
    uds = UdsClient(panda, MQB_EPS_CAN_ADDR, MQB_EPS_CAN_ADDR + RX_OFFSET, bus, timeout=0.5)

    # Enter extended diagnostic session
    print("\n[2/5] Entering extended diagnostic session (0x03)...")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        print("  OK")
    except MessageTimeoutError:
        print("  TIMEOUT — is ignition on?")
        sys.exit(1)
    except NegativeResponseError as e:
        print(f"  REJECTED: {e.message} (error 0x{e.error_code:02x})")
        sys.exit(1)

    # Request seed at level 0x11
    print("\n[3/5] Requesting seed at level 0x11...")
    try:
        seed_bytes = uds.security_access(SA_REQUEST_SEED)
        seed_int = struct.unpack("!I", seed_bytes)[0]
        print(f"  Seed: 0x{seed_int:08x}")
    except NegativeResponseError as e:
        print(f"  REJECTED: {e.message} (error 0x{e.error_code:02x})")
        sys.exit(1)
    except MessageTimeoutError:
        print("  TIMEOUT")
        sys.exit(1)

    if seed_int == 0:
        print("  Seed is zero — already unlocked!")
        sys.exit(0)

    # Compute key
    key_int = compute_key_level_0x11(seed_int)
    key_bytes = struct.pack("!I", key_int)
    print(f"\n[4/5] Computed key: 0x{key_int:08x}")
    print(f"  Sending key...")

    # Send key at level 0x12
    try:
        uds.security_access(SA_SEND_KEY, security_key=key_bytes)
        print("  *** SUCCESS — Level 0x11 UNLOCKED! ***")
    except NegativeResponseError as e:
        print(f"  REJECTED: {e.message} (error 0x{e.error_code:02x})")
        if e.error_code == 0x35:
            print("  (0x35 = invalidKey — algorithm is WRONG for this ECU)")
        elif e.error_code == 0x36:
            print("  (0x36 = exceededNumberOfAttempts — ECU locked, power cycle to reset)")
        elif e.error_code == 0x37:
            print("  (0x37 = requiredTimeDelayNotExpired — wait and retry)")
        sys.exit(1)
    except MessageTimeoutError:
        print("  TIMEOUT (unexpected)")
        sys.exit(1)

    # Probe what's available now
    print("\n[5/5] Probing available services after unlock...")

    # Try programming session
    print("\n  Attempting programming session (0x02)...")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.PROGRAMMING)
        print("  Programming session: OK")
    except NegativeResponseError as e:
        print(f"  Programming session: REJECTED ({e.message}, error 0x{e.error_code:02x})")
    except MessageTimeoutError:
        print("  Programming session: TIMEOUT")

    # Try READ_MEMORY_BY_ADDRESS (small test read at address 0x00000000, 16 bytes)
    print("\n  Attempting READ_MEMORY_BY_ADDRESS at 0x00000000 (16 bytes)...")
    try:
        # Service 0x23, addressAndLengthFormatIdentifier=0x44 (4-byte addr, 4-byte len)
        data = bytes([0x44]) + struct.pack("!I", 0x00000000) + struct.pack("!I", 16)
        resp = uds._uds_request(0x23, data=data)
        print(f"  READ_MEMORY: OK — got {len(resp)} bytes: {resp.hex()}")
    except NegativeResponseError as e:
        print(f"  READ_MEMORY: REJECTED ({e.message}, error 0x{e.error_code:02x})")
    except MessageTimeoutError:
        print("  READ_MEMORY: TIMEOUT")

    # Try ROUTINE_CONTROL — check erase memory (just identification, don't start it)
    print("\n  Attempting ROUTINE_CONTROL identify (0x31 03 FF00)...")
    try:
        resp = uds._uds_request(0x31, subfunction=0x03, data=bytes([0xFF, 0x00]))
        print(f"  ROUTINE_CONTROL: OK — response: {resp.hex()}")
    except NegativeResponseError as e:
        print(f"  ROUTINE_CONTROL: REJECTED ({e.message}, error 0x{e.error_code:02x})")
    except MessageTimeoutError:
        print("  ROUTINE_CONTROL: TIMEOUT")

    print("\n=== Done ===")


if __name__ == "__main__":
    main()
