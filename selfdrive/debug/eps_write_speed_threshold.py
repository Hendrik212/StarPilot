#!/usr/bin/env python3
"""
VW Crafter MK2 ZFLS EPS — Write HCA speed threshold (DID 0x1812).

Attempts to lower the HCA minimum speed from 57 km/h to 32 km/h
by writing DID 0x1812 with F9 20 01 (upper=249, lower=32, enabled).

Tries level 0x03 (coding) first. If that fails, falls back to level 0x11.

Usage:
  Stop openpilot first:  sudo kill $(pgrep -f 'pandad|manager')
  Run:  /usr/local/venv/bin/python3 selfdrive/debug/eps_write_speed_threshold.py
"""

import struct
import sys
from datetime import date
from opendbc.car.uds import UdsClient, MessageTimeoutError, NegativeResponseError, SESSION_TYPE, \
    DATA_IDENTIFIER_TYPE, ACCESS_TYPE, SERVICE_TYPE
from opendbc.car.structs import CarParams
from panda import Panda

MQB_EPS_CAN_ADDR = 0x712
RX_OFFSET = 0x6a

DID_HCA_SPEED = 0x1812
DID_HCA_SPEED_EXT = 0x1827

ORIGINAL_VALUE = bytes([0xF9, 0x39, 0x01])  # upper=249, lower=57, enabled
NEW_VALUE = bytes([0xF9, 0x20, 0x01])       # upper=249, lower=32, enabled

# Level 0x03 security access (coding level)
SA_03_REQUEST_SEED = ACCESS_TYPE.REQUEST_SEED + 2  # 0x03
SA_03_SEND_KEY = ACCESS_TYPE.SEND_KEY + 2          # 0x04
SA_03_KEY_ALGO = lambda seed_int: (seed_int + 28183) & 0xFFFFFFFF

# Level 0x11 security access (programming level)
SA_11_REQUEST_SEED = 0x11
SA_11_SEND_KEY = 0x12
SA_11_KEY_ALGO = lambda seed_int: seed_int & 0xFFFFFFFF


def read_did(uds, did):
    """Read a DID using raw UDS request (bypasses enum check)."""
    resp = uds._uds_request(SERVICE_TYPE.READ_DATA_BY_IDENTIFIER, data=struct.pack("!H", did))
    return resp[2:]  # strip echoed DID bytes


def write_did(uds, did, value):
    """Write a DID using raw UDS request (bypasses enum check)."""
    data = struct.pack("!H", did) + value
    resp = uds._uds_request(SERVICE_TYPE.WRITE_DATA_BY_IDENTIFIER, data=data)
    resp_did = struct.unpack("!H", resp[0:2])[0] if len(resp) >= 2 else None
    if resp_did != did:
        raise ValueError(f"Write response DID mismatch: expected 0x{did:04x}, got 0x{resp_did:04x}")
    return resp


def unlock_level_03(uds):
    """Unlock security access level 0x03 (coding)."""
    print("  Requesting seed at level 0x03...")
    seed_bytes = uds.security_access(SA_03_REQUEST_SEED)
    seed_int = struct.unpack("!I", seed_bytes)[0]
    print(f"  Seed: 0x{seed_int:08x}")

    if seed_int == 0:
        print("  Already unlocked!")
        return True

    key_int = SA_03_KEY_ALGO(seed_int)
    key_bytes = struct.pack("!I", key_int)
    print(f"  Key:  0x{key_int:08x}  (seed + 28183)")
    uds.security_access(SA_03_SEND_KEY, security_key=key_bytes)
    print("  Level 0x03 UNLOCKED")
    return True


def unlock_level_11(uds):
    """Unlock security access level 0x11 (programming)."""
    print("  Requesting seed at level 0x11...")
    seed_bytes = uds.security_access(SA_11_REQUEST_SEED)
    seed_int = struct.unpack("!I", seed_bytes)[0]
    print(f"  Seed: 0x{seed_int:08x}")

    if seed_int == 0:
        print("  Already unlocked!")
        return True

    key_bytes = seed_bytes  # identity
    print(f"  Key:  0x{seed_int:08x}  (= seed)")
    uds.security_access(SA_11_SEND_KEY, security_key=key_bytes)
    print("  Level 0x11 UNLOCKED")
    return True


def write_preconditions(uds):
    """Write programming date and tester ID (required before DID writes on VW)."""
    print("  Writing programming date + tester ID (VW write precondition)...")
    current_date = date.today()
    formatted_date = current_date.strftime('%y-%m-%d')
    year, month, day = (int(part) for part in formatted_date.split('-'))
    prog_date = bytes([year, month, day])
    uds.write_data_by_identifier(DATA_IDENTIFIER_TYPE.PROGRAMMING_DATE, prog_date)

    tester_num = uds.read_data_by_identifier(
        DATA_IDENTIFIER_TYPE.CALIBRATION_REPAIR_SHOP_CODE_OR_CALIBRATION_EQUIPMENT_SERIAL_NUMBER
    )
    uds.write_data_by_identifier(
        DATA_IDENTIFIER_TYPE.REPAIR_SHOP_CODE_OR_TESTER_SERIAL_NUMBER, tester_num
    )
    print("  Preconditions written OK")


def attempt_write(uds, unlock_fn, level_name):
    """Attempt the full write sequence with a given security level."""
    print(f"\n{'='*60}")
    print(f"  ATTEMPTING WRITE WITH {level_name}")
    print(f"{'='*60}")

    # Unlock
    try:
        unlock_fn(uds)
    except NegativeResponseError as e:
        print(f"  Unlock FAILED: {e.message} (0x{e.error_code:02x})")
        return False
    except MessageTimeoutError:
        print("  Unlock TIMEOUT")
        return False

    # Write preconditions
    try:
        write_preconditions(uds)
    except NegativeResponseError as e:
        print(f"  Precondition write FAILED: {e.message} (0x{e.error_code:02x})")
        print("  Skipping preconditions, trying DID write directly...")
    except MessageTimeoutError:
        print("  Precondition write TIMEOUT, trying DID write directly...")

    # Write DID 0x1812
    print(f"\n  Writing DID 0x{DID_HCA_SPEED:04x} = {NEW_VALUE.hex()}...")
    try:
        write_did(uds, DID_HCA_SPEED, NEW_VALUE)
        print(f"  *** WRITE SUCCESS ***")
        return True
    except NegativeResponseError as e:
        print(f"  Write REJECTED: {e.message} (0x{e.error_code:02x})")
        error_hints = {
            0x31: "requestOutOfRange — DID may not be writable",
            0x33: "securityAccessDenied — need different security level",
            0x72: "generalProgrammingFailure",
            0x22: "conditionsNotCorrect — may need programming session or other precondition",
            0x24: "requestSequenceError — precondition writes may be required in different order",
            0x13: "incorrectMessageLengthOrInvalidFormat — data format wrong",
            0x11: "serviceNotSupported",
            0x7F: "serviceNotSupportedInActiveSession",
        }
        if e.error_code in error_hints:
            print(f"  Hint: {error_hints[e.error_code]}")
        return False
    except MessageTimeoutError:
        print("  Write TIMEOUT")
        return False


def main():
    print("=== VW Crafter MK2 EPS — HCA Speed Threshold Write ===\n")
    print(f"  Target DID:     0x{DID_HCA_SPEED:04x}")
    print(f"  Current value:  {ORIGINAL_VALUE.hex()}  (upper=249, lower=57 km/h, enabled)")
    print(f"  New value:      {NEW_VALUE.hex()}  (upper=249, lower=32 km/h, enabled)")

    # Connect
    print("\n[1/5] Connecting to panda...")
    try:
        panda = Panda()
        panda.set_safety_mode(CarParams.SafetyModel.elm327)
    except Exception as e:
        print(f"  FAILED: {e}")
        sys.exit(1)
    bus = 1 if panda.has_obd() else 0
    print(f"  OK — bus={bus}")

    uds = UdsClient(panda, MQB_EPS_CAN_ADDR, MQB_EPS_CAN_ADDR + RX_OFFSET, bus, timeout=0.5)

    # Enter extended diagnostic session
    print("\n[2/5] Entering extended diagnostic session...")
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        print("  OK")
    except MessageTimeoutError:
        print("  TIMEOUT — is ignition on?")
        sys.exit(1)
    except NegativeResponseError as e:
        print(f"  REJECTED: {e.message} (0x{e.error_code:02x})")
        sys.exit(1)

    # Read current value
    print(f"\n[3/5] Reading current DID 0x{DID_HCA_SPEED:04x}...")
    try:
        current = read_did(uds, DID_HCA_SPEED)
        print(f"  Current: {current.hex()}  (upper={current[0]}, lower={current[1]}, flag={current[2]})")

        if current != ORIGINAL_VALUE:
            print(f"\n  WARNING: current value does not match expected {ORIGINAL_VALUE.hex()}")
            print(f"  Proceeding anyway, but note the original value for rollback: {current.hex()}")
    except NegativeResponseError as e:
        print(f"  Read FAILED: {e.message} (0x{e.error_code:02x})")
        sys.exit(1)
    except MessageTimeoutError:
        print("  Read TIMEOUT")
        sys.exit(1)

    # Also read 0x1827 for reference
    try:
        ext = read_did(uds, DID_HCA_SPEED_EXT)
        print(f"  DID 0x{DID_HCA_SPEED_EXT:04x}: {ext.hex()}")
    except Exception:
        pass

    # Attempt write with level 0x03
    print("\n[4/5] Attempting write...")
    # Re-enter extended session (security access may have changed session state)
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)

    success = attempt_write(uds, unlock_level_03, "LEVEL 0x03 (coding)")

    if not success:
        print("\n  Level 0x03 failed. Trying level 0x11...")
        # Re-enter extended session
        try:
            uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        except Exception:
            pass
        success = attempt_write(uds, unlock_level_11, "LEVEL 0x11 (programming)")

    if not success:
        print("\n  Both levels failed. Write not possible with current approach.")
        print("  See error messages above for hints on what to try next.")
        sys.exit(1)

    # Read back to verify
    print(f"\n[5/5] Reading back DID 0x{DID_HCA_SPEED:04x}...")
    try:
        # Re-enter session and re-auth (write may have changed state)
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        readback = read_did(uds, DID_HCA_SPEED)
        print(f"  Readback: {readback.hex()}  (upper={readback[0]}, lower={readback[1]}, flag={readback[2]})")

        if readback == NEW_VALUE:
            print(f"\n  *** VERIFIED — new speed threshold active ***")
            print(f"  Lower HCA limit is now {readback[1]} km/h (was {ORIGINAL_VALUE[1]} km/h)")
            print(f"\n  To restore original: change NEW_VALUE to {ORIGINAL_VALUE.hex()} and re-run")
        elif readback == ORIGINAL_VALUE:
            print(f"\n  WARNING: readback shows ORIGINAL value — write may not have persisted")
        else:
            print(f"\n  Unexpected readback value: {readback.hex()}")
    except Exception as e:
        print(f"  Readback failed: {e}")

    # Also read 0x1827 after write
    try:
        ext_after = read_did(uds, DID_HCA_SPEED_EXT)
        print(f"  DID 0x{DID_HCA_SPEED_EXT:04x} after: {ext_after.hex()}")
    except Exception:
        pass

    print("\n=== Done ===")
    print("Turn ignition off and on, then test HCA at speeds below 50 km/h")


if __name__ == "__main__":
    main()
