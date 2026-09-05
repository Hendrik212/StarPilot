#!/usr/bin/env python3
"""
CAN bus sniffer for capturing UDS seed-key exchanges on the VW MQB EPS.

Filters for EPS traffic on 0x712 (TX to EPS) and 0x77C (RX from EPS).
Specifically watches for SecurityAccess (service 0x27) seed-key pairs.

Logs all EPS traffic to a timestamped file + prints to console.
Handles ISO-TP multi-frame reassembly for longer messages.

Usage:
  PYTHONPATH=/data/openpilot:/data/openpilot/opendbc_repo \
    /usr/local/venv/bin/python3 /data/openpilot/selfdrive/debug/eps_can_sniff.py

Press Ctrl+C to stop. Log file saved to /tmp/eps_sniff_<timestamp>.log
"""

import time
import sys
import os
from datetime import datetime
from opendbc.car.structs import CarParams
from panda import Panda

EPS_TX = 0x712   # ODIS -> EPS
EPS_RX = 0x77C   # EPS -> ODIS

# UDS service IDs we care about
SVC_SECURITY_ACCESS = 0x27
SVC_SECURITY_ACCESS_RESP = 0x67
SVC_DIAG_SESSION = 0x10
SVC_DIAG_SESSION_RESP = 0x50
SVC_NEGATIVE_RESP = 0x7F

# Also capture all other UDS traffic for context
WATCH_ADDRS = {EPS_TX, EPS_RX}

# ISO-TP frame types
ISOTP_SINGLE = 0
ISOTP_FIRST = 1
ISOTP_CONSECUTIVE = 2
ISOTP_FLOW = 3


class IsotpReassembler:
    """Simple ISO-TP multi-frame reassembly."""
    def __init__(self):
        self.pending = {}  # addr -> {total_len, data, next_seq}

    def process(self, addr, raw):
        frame_type = (raw[0] >> 4) & 0xF

        if frame_type == ISOTP_SINGLE:
            length = raw[0] & 0x0F
            return raw[1:1+length]

        elif frame_type == ISOTP_FIRST:
            total_len = ((raw[0] & 0x0F) << 8) | raw[1]
            self.pending[addr] = {
                'total_len': total_len,
                'data': bytearray(raw[2:]),
                'next_seq': 1,
            }
            return None  # incomplete

        elif frame_type == ISOTP_CONSECUTIVE:
            seq = raw[0] & 0x0F
            if addr in self.pending:
                p = self.pending[addr]
                if seq == p['next_seq'] & 0x0F:
                    p['data'].extend(raw[1:])
                    p['next_seq'] += 1
                    if len(p['data']) >= p['total_len']:
                        result = bytes(p['data'][:p['total_len']])
                        del self.pending[addr]
                        return result
            return None  # incomplete

        elif frame_type == ISOTP_FLOW:
            return None  # flow control, ignore

        return None


def decode_uds(payload, direction):
    """Decode UDS payload into human-readable description."""
    if len(payload) < 1:
        return "empty"

    svc = payload[0]

    if svc == SVC_SECURITY_ACCESS:
        if len(payload) >= 2:
            sublevel = payload[1]
            if sublevel % 2 == 1:  # odd = request seed
                return f"SECURITY_ACCESS requestSeed level=0x{sublevel:02x}"
            else:  # even = send key
                key_data = payload[2:]
                return f"SECURITY_ACCESS sendKey level=0x{sublevel:02x} KEY={key_data.hex()}"
        return "SECURITY_ACCESS (truncated)"

    elif svc == SVC_SECURITY_ACCESS_RESP:
        if len(payload) >= 2:
            sublevel = payload[1]
            if sublevel % 2 == 1:  # odd = seed response
                seed_data = payload[2:]
                return f"SECURITY_ACCESS_RESP seed level=0x{sublevel:02x} SEED={seed_data.hex()}"
            else:  # even = key accepted
                return f"SECURITY_ACCESS_RESP keyAccepted level=0x{sublevel:02x}"
        return "SECURITY_ACCESS_RESP (truncated)"

    elif svc == SVC_DIAG_SESSION:
        session = payload[1] if len(payload) > 1 else 0
        names = {1: "DEFAULT", 2: "PROGRAMMING", 3: "EXTENDED"}
        return f"DiagSessionControl session=0x{session:02x} ({names.get(session, '?')})"

    elif svc == SVC_DIAG_SESSION_RESP:
        session = payload[1] if len(payload) > 1 else 0
        names = {1: "DEFAULT", 2: "PROGRAMMING", 3: "EXTENDED"}
        return f"DiagSessionControl_RESP session=0x{session:02x} ({names.get(session, '?')})"

    elif svc == SVC_NEGATIVE_RESP:
        rejected_svc = payload[1] if len(payload) > 1 else 0
        error = payload[2] if len(payload) > 2 else 0
        error_names = {
            0x10: "generalReject", 0x11: "serviceNotSupported",
            0x12: "subFunctionNotSupported", 0x13: "incorrectMessageLength",
            0x22: "conditionsNotCorrect", 0x24: "requestSequenceError",
            0x31: "requestOutOfRange", 0x35: "invalidKey",
            0x36: "exceededNumberOfAttempts", 0x37: "requiredTimeDelayNotExpired",
            0x72: "generalProgrammingFailure", 0x78: "requestCorrectlyReceived-ResponsePending",
        }
        return f"NEGATIVE_RESP svc=0x{rejected_svc:02x} error=0x{error:02x} ({error_names.get(error, '?')})"

    else:
        return f"svc=0x{svc:02x} data={payload[1:].hex()}"


def main():
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    logfile = f"/tmp/eps_sniff_{timestamp}.log"

    print(f"=== VW MQB EPS CAN Sniffer ===")
    print(f"Watching: 0x{EPS_TX:03x} (ODIS->EPS) and 0x{EPS_RX:03x} (EPS->ODIS)")
    print(f"Log file: {logfile}")
    print(f"Press Ctrl+C to stop\n")

    panda = Panda()
    panda.set_safety_mode(CarParams.SafetyModel.elm327)
    bus = 1 if panda.has_obd() else 0
    print(f"Panda connected, bus={bus}")

    # Clear buffers
    panda.can_clear(bus)
    panda.can_clear(0xFFFF)

    reassembler = IsotpReassembler()
    seed_key_pairs = []  # collected (level, seed, key) tuples
    current_seed = {}    # level -> seed bytes

    f = open(logfile, "w")
    header = f"# EPS CAN sniff started {datetime.now().isoformat()}\n"
    header += f"# Watching 0x{EPS_TX:03x} / 0x{EPS_RX:03x} on bus {bus}\n\n"
    f.write(header)
    print(header, end="")

    try:
        start = time.time()
        msg_count = 0
        while True:
            msgs = panda.can_recv() or []
            for addr, data, msg_bus in msgs:
                if msg_bus != bus:
                    continue
                if addr not in WATCH_ADDRS:
                    continue

                data = bytes(data)
                elapsed = time.time() - start
                direction = "TX>EPS" if addr == EPS_TX else "EPS>RX"
                msg_count += 1

                # Log raw frame
                raw_line = f"[{elapsed:10.3f}] 0x{addr:03x} [{direction}] {data.hex()}"
                f.write(raw_line + "\n")
                print(raw_line)

                # Try ISO-TP reassembly
                payload = reassembler.process(addr, data)
                if payload:
                    decoded = decode_uds(payload, direction)
                    uds_line = f"             >>> UDS: {decoded}"
                    f.write(uds_line + "\n")
                    print(uds_line)

                    # Track seed-key pairs
                    if payload[0] == SVC_SECURITY_ACCESS_RESP and len(payload) >= 2:
                        sublevel = payload[1]
                        if sublevel % 2 == 1:  # seed
                            current_seed[sublevel] = payload[2:]

                    if payload[0] == SVC_SECURITY_ACCESS and len(payload) >= 2:
                        sublevel = payload[1]
                        if sublevel % 2 == 0:  # key being sent
                            seed_level = sublevel - 1
                            key_data = payload[2:]
                            if seed_level in current_seed:
                                pair = {
                                    'level': seed_level,
                                    'seed': current_seed[seed_level],
                                    'key': key_data,
                                }
                                seed_key_pairs.append(pair)
                                highlight = f"\n{'='*60}\n"
                                highlight += f"*** CAPTURED SEED-KEY PAIR ***\n"
                                highlight += f"  Level: 0x{seed_level:02x}\n"
                                highlight += f"  Seed:  {current_seed[seed_level].hex()}\n"
                                highlight += f"  Key:   {key_data.hex()}\n"
                                highlight += f"{'='*60}\n"
                                f.write(highlight)
                                print(highlight)

                f.flush()

            time.sleep(0.001)

    except KeyboardInterrupt:
        pass

    # Summary
    summary = f"\n\n=== Summary ===\n"
    summary += f"Total EPS frames captured: {msg_count}\n"
    summary += f"Duration: {time.time() - start:.1f}s\n"
    summary += f"Seed-key pairs captured: {len(seed_key_pairs)}\n"
    for i, pair in enumerate(seed_key_pairs):
        summary += f"\n  Pair {i+1}:\n"
        summary += f"    Level: 0x{pair['level']:02x}\n"
        summary += f"    Seed:  {pair['seed'].hex()}\n"
        summary += f"    Key:   {pair['key'].hex()}\n"
    summary += f"\nLog saved to: {logfile}\n"

    f.write(summary)
    f.close()
    print(summary)


if __name__ == "__main__":
    main()
