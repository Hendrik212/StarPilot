#!/usr/bin/env python3
"""
Probe available UDS services on the VW Crafter MK2 EPS after level 0x11 unlock.
All operations are READ-ONLY — no writes, no routine starts, no downloads.

Usage:
  sudo kill $(pidof python3) 2>/dev/null
  PYTHONPATH=/data/openpilot:/data/openpilot/opendbc_repo \
    /usr/local/venv/bin/python3 -u /data/openpilot/selfdrive/debug/eps_probe_unlocked.py
"""

import struct
import time
import sys
from opendbc.car.uds import UdsClient, MessageTimeoutError, NegativeResponseError, SESSION_TYPE
from opendbc.car.structs import CarParams
from panda import Panda

MQB_EPS_CAN_ADDR = 0x712
RX_OFFSET = 0x6a
SA_REQUEST_SEED = 0x11
SA_SEND_KEY = 0x12


def unlock(uds):
    """Enter extended session and unlock level 0x11."""
    print("[*] Entering extended diagnostic session...")
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    print("    OK")

    print("[*] Requesting seed at level 0x11...")
    seed_bytes = uds.security_access(SA_REQUEST_SEED)
    seed_int = struct.unpack("!I", seed_bytes)[0]
    print(f"    Seed: 0x{seed_int:08x}")

    if seed_int == 0:
        print("    Already unlocked!")
        return True

    key_bytes = seed_bytes  # key = seed
    print(f"[*] Sending key (=seed)...")
    uds.security_access(SA_SEND_KEY, security_key=key_bytes)
    print("    UNLOCKED!")
    return True


def keepalive(uds):
    """Send TesterPresent to keep session alive."""
    try:
        uds._uds_request(0x3E, subfunction=0x00)
    except Exception:
        pass


def probe_service(uds, svc_id, name, data=b'', subfunction=None):
    """Probe a single UDS service. Returns (supported, response_or_error)."""
    try:
        if subfunction is not None:
            resp = uds._uds_request(svc_id, subfunction=subfunction, data=data)
        else:
            resp = uds._uds_request(svc_id, data=data)
        return True, resp
    except NegativeResponseError as e:
        return False, e
    except MessageTimeoutError:
        return False, "TIMEOUT"


def main():
    print("=== VW Crafter MK2 EPS — Unlocked Service Probe ===\n")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    bus = 1 if panda.has_obd() else 0
    uds = UdsClient(panda, MQB_EPS_CAN_ADDR, MQB_EPS_CAN_ADDR + RX_OFFSET, bus, timeout=0.5)

    if not unlock(uds):
        sys.exit(1)

    # --- 1. Scan all UDS service IDs ---
    print("\n--- Scanning UDS services (0x10-0x3E) ---\n")
    services = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x14: "ClearDiagnosticInformation",
        0x19: "ReadDTCInformation",
        0x22: "ReadDataByIdentifier",
        0x23: "ReadMemoryByAddress",
        0x24: "ReadScalingDataByIdentifier",
        0x27: "SecurityAccess",
        0x28: "CommunicationControl",
        0x2A: "ReadDataByPeriodicIdentifier",
        0x2C: "DynamicallyDefineDataIdentifier",
        0x2E: "WriteDataByIdentifier",
        0x2F: "InputOutputControlByIdentifier",
        0x31: "RoutineControl",
        0x34: "RequestDownload",
        0x35: "RequestUpload",
        0x36: "TransferData",
        0x37: "RequestTransferExit",
        0x38: "RequestFileTransfer",
        0x3D: "WriteMemoryByAddress",
        0x3E: "TesterPresent",
    }

    for svc_id, name in sorted(services.items()):
        keepalive(uds)
        # Use minimal valid request for each service
        if svc_id == 0x22:
            ok, resp = probe_service(uds, svc_id, name, data=bytes([0xF1, 0x90]))
        elif svc_id == 0x23:
            # ReadMemoryByAddress: format=0x44 (4-byte addr, 4-byte len), addr=0, len=1
            ok, resp = probe_service(uds, svc_id, name, data=bytes([0x44]) + b'\x00'*4 + b'\x00\x00\x00\x01')
        elif svc_id == 0x27:
            ok, resp = probe_service(uds, svc_id, name, subfunction=0x11)
        elif svc_id == 0x31:
            # RoutineControl: requestResults (0x03) for routine 0x0203
            ok, resp = probe_service(uds, svc_id, name, subfunction=0x03, data=bytes([0x02, 0x03]))
        elif svc_id == 0x34:
            # RequestDownload: format=0x00, addr=0, len=0
            ok, resp = probe_service(uds, svc_id, name, data=bytes([0x00, 0x44]) + b'\x00'*4 + b'\x00\x00\x00\x01')
        elif svc_id == 0x35:
            # RequestUpload
            ok, resp = probe_service(uds, svc_id, name, data=bytes([0x00, 0x44]) + b'\x00'*4 + b'\x00\x00\x00\x01')
        elif svc_id in (0x10, 0x11, 0x28):
            ok, resp = probe_service(uds, svc_id, name, subfunction=0x01)
        elif svc_id == 0x19:
            ok, resp = probe_service(uds, svc_id, name, subfunction=0x02, data=bytes([0xFF]))
        elif svc_id == 0x3E:
            ok, resp = probe_service(uds, svc_id, name, subfunction=0x00)
        else:
            ok, resp = probe_service(uds, svc_id, name)

        if ok:
            resp_hex = resp.hex() if isinstance(resp, bytes) else str(resp)
            print(f"  [OK]  0x{svc_id:02x} {name}: {resp_hex[:80]}")
        else:
            if isinstance(resp, NegativeResponseError):
                err = f"0x{resp.error_code:02x}"
                if resp.error_code == 0x11:
                    status = "not supported"
                elif resp.error_code == 0x12:
                    status = "sub-function not supported"
                elif resp.error_code == 0x22:
                    status = "conditions not correct"
                elif resp.error_code == 0x31:
                    status = "request out of range"
                elif resp.error_code == 0x33:
                    status = "security access denied"
                elif resp.error_code == 0x7F:
                    status = "service not supported in active session"
                else:
                    status = resp.message
                print(f"  [---] 0x{svc_id:02x} {name}: {status} ({err})")
            else:
                print(f"  [---] 0x{svc_id:02x} {name}: {resp}")

    # --- 2. Try programming session after unlock ---
    print("\n--- Programming session attempt ---\n")
    keepalive(uds)
    # Re-unlock in case session dropped
    try:
        seed_bytes = uds.security_access(SA_REQUEST_SEED)
        seed_int = struct.unpack("!I", seed_bytes)[0]
        if seed_int != 0:
            uds.security_access(SA_SEND_KEY, security_key=seed_bytes)
            print("  Re-unlocked level 0x11")
        else:
            print("  Still unlocked")
    except Exception as e:
        print(f"  Re-unlock failed: {e}")

    ok, resp = probe_service(uds, 0x10, "Programming", subfunction=0x02)
    if ok:
        print(f"  Programming session: OK!")
    else:
        if isinstance(resp, NegativeResponseError):
            print(f"  Programming session: {resp.message} (0x{resp.error_code:02x})")
        else:
            print(f"  Programming session: {resp}")

    # --- 3. Scan routine IDs ---
    print("\n--- Scanning routine IDs (read-only: requestResults 0x03) ---\n")
    # Re-enter extended session and re-unlock
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        seed_bytes = uds.security_access(SA_REQUEST_SEED)
        seed_int = struct.unpack("!I", seed_bytes)[0]
        if seed_int != 0:
            uds.security_access(SA_SEND_KEY, security_key=seed_bytes)
    except Exception:
        pass

    found_routines = []
    # Scan common VW routine ranges
    routine_ranges = [
        (0x0200, 0x0210),  # common VW
        (0x0300, 0x0310),
        (0xDF00, 0xDF10),
        (0xF000, 0xF010),
        (0xFF00, 0xFF10),
    ]
    for start, end in routine_ranges:
        for rid in range(start, end):
            keepalive(uds)
            ok, resp = probe_service(uds, 0x31, f"Routine 0x{rid:04x}", subfunction=0x03, data=struct.pack("!H", rid))
            if ok:
                resp_hex = resp.hex() if isinstance(resp, bytes) else str(resp)
                print(f"  [OK]  Routine 0x{rid:04x}: {resp_hex}")
                found_routines.append(rid)
            elif isinstance(resp, NegativeResponseError):
                if resp.error_code not in (0x11, 0x31, 0x12):  # skip "not supported" / "out of range"
                    print(f"  [?]   Routine 0x{rid:04x}: 0x{resp.error_code:02x} {resp.message}")

    # --- 4. Scan interesting data identifiers ---
    print("\n--- Reading additional data identifiers ---\n")
    # Re-enter extended session and re-unlock
    try:
        uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
        seed_bytes = uds.security_access(SA_REQUEST_SEED)
        seed_int = struct.unpack("!I", seed_bytes)[0]
        if seed_int != 0:
            uds.security_access(SA_SEND_KEY, security_key=seed_bytes)
    except Exception:
        pass

    dids = [
        (0x0600, "Coding"),
        (0x0606, "Coding variant"),
        (0xF186, "ActiveDiagnosticSession"),
        (0xF187, "SparePartNumber"),
        (0xF188, "ECUSoftwareNumber"),
        (0xF189, "ECUSoftwareVersion"),
        (0xF18A, "SystemSupplierID"),
        (0xF18B, "ECUManufacturingDate"),
        (0xF18C, "ECUSerialNumber"),
        (0xF190, "VIN"),
        (0xF191, "HardwarePartNumber"),
        (0xF197, "SystemNameEngineType"),
        (0xF19E, "ASAMDataset"),
        (0xF1A0, "?_F1A0"),
        (0xF1A2, "?_F1A2"),
        (0xF1A4, "?_F1A4"),
        (0xF1A5, "?_F1A5"),
        (0xF1AA, "?_F1AA"),
        (0xF1AB, "?_F1AB"),
        (0xF1DF, "?_F1DF"),
        (0xF1E0, "?_F1E0"),
        (0x0200, "?_0200"),
        (0x0201, "?_0201"),
        (0x0202, "?_0202"),
        (0x0203, "?_0203"),
        (0x0204, "?_0204"),
        (0x0205, "?_0205"),
        (0xFD01, "?_FD01"),
        (0xFD02, "?_FD02"),
        (0xFD10, "?_FD10"),
        (0xFD11, "?_FD11"),
    ]

    for did, name in dids:
        keepalive(uds)
        ok, resp = probe_service(uds, 0x22, name, data=struct.pack("!H", did))
        if ok:
            resp_hex = resp.hex() if isinstance(resp, bytes) else ""
            # Try to decode as ASCII
            try:
                ascii_str = resp[2:].decode('ascii', errors='replace').rstrip('\x00')
                print(f"  [OK]  0x{did:04x} {name}: {resp_hex}  ({ascii_str})")
            except Exception:
                print(f"  [OK]  0x{did:04x} {name}: {resp_hex}")
        elif isinstance(resp, NegativeResponseError) and resp.error_code not in (0x11, 0x31):
            print(f"  [---] 0x{did:04x} {name}: 0x{resp.error_code:02x}")

    print("\n=== Probe complete ===")
    if found_routines:
        print(f"Found routines: {[f'0x{r:04x}' for r in found_routines]}")


if __name__ == "__main__":
    main()
