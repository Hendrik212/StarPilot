#!/usr/bin/env python3
"""
Broad DID (Data Identifier) scan on VW Crafter MK2 EPS after level 0x11 unlock.
Scans all 65536 DIDs via ReadDataByIdentifier (0x22) — completely read-only.

Outputs all responding DIDs with their data.

Usage:
  sudo kill $(pidof python3) 2>/dev/null
  PYTHONPATH=/data/openpilot:/data/openpilot/opendbc_repo \
    /usr/local/venv/bin/python3 -u /data/openpilot/selfdrive/debug/eps_did_scan.py
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

LOGFILE = "/tmp/eps_did_scan.log"


def unlock(uds):
    uds.diagnostic_session_control(SESSION_TYPE.EXTENDED_DIAGNOSTIC)
    seed_bytes = uds.security_access(SA_REQUEST_SEED)
    seed_int = struct.unpack("!I", seed_bytes)[0]
    if seed_int != 0:
        uds.security_access(SA_SEND_KEY, security_key=seed_bytes)
    print("[*] Level 0x11 unlocked")


def keepalive(uds):
    try:
        uds._uds_request(0x3E, subfunction=0x00)
    except Exception:
        pass


def main():
    print(f"=== VW Crafter MK2 EPS — Full DID Scan ===")
    print(f"Log: {LOGFILE}\n")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    bus = 1 if panda.has_obd() else 0
    uds = UdsClient(panda, MQB_EPS_CAN_ADDR, MQB_EPS_CAN_ADDR + RX_OFFSET, bus, timeout=0.2)

    unlock(uds)

    found = []
    f = open(LOGFILE, "w")
    f.write("# EPS DID Scan — VW Crafter MK2 (2N0909144J / EV_SteerAssisMNB)\n")
    f.write(f"# Started: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")

    ka_counter = 0
    reauth_counter = 0
    total = 0x10000

    for did in range(0x0000, 0x10000):
        ka_counter += 1
        reauth_counter += 1

        # Keepalive every 10 requests
        if ka_counter >= 10:
            keepalive(uds)
            ka_counter = 0

        # Re-unlock every 500 requests (session might timeout)
        if reauth_counter >= 500:
            try:
                unlock(uds)
            except Exception:
                try:
                    time.sleep(0.5)
                    unlock(uds)
                except Exception as e:
                    print(f"\n  [!] Re-unlock failed at DID 0x{did:04x}: {e}")
            reauth_counter = 0

        # Progress indicator
        if did % 0x1000 == 0:
            pct = (did / total) * 100
            print(f"  Scanning 0x{did:04x}... ({pct:.0f}%) found={len(found)}")

        try:
            resp = uds._uds_request(0x22, data=struct.pack("!H", did))
            resp_hex = resp.hex()

            # Try ASCII decode
            try:
                ascii_part = resp[2:].decode('ascii', errors='replace').rstrip('\x00 ')
            except Exception:
                ascii_part = ""

            line = f"0x{did:04x}  len={len(resp):3d}  {resp_hex}"
            if ascii_part and all(c.isprintable() for c in ascii_part):
                line += f"  # {ascii_part}"

            f.write(line + "\n")
            f.flush()
            print(f"  [OK] {line}")
            found.append((did, resp))

        except NegativeResponseError:
            pass  # expected for most DIDs
        except MessageTimeoutError:
            pass  # also expected

    summary = f"\n# Scan complete. Found {len(found)} readable DIDs.\n"
    f.write(summary)
    f.close()

    print(f"\n=== Done. {len(found)} DIDs found. Log: {LOGFILE} ===")


if __name__ == "__main__":
    main()
