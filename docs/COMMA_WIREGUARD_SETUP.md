# Comma 3X WireGuard Setup (hand-rolled /data/wgs tunnel)

Complete reference for the WireGuard client running on the Ioniq comma 3X
(`ioniq_local`, 192.168.1.197). Replicating this on another comma 3X (e.g. the
VW device) requires only dropping in a new `wgs_client.wg.conf` with that
device's own keys/address — everything else is car-agnostic.

> **Secrets note:** all PrivateKey / PresharedKey values are redacted here.
> Live files live on the device at `/data/wgs/etc/` (mode 0600).

---

## 1. What it is

A **userspace WireGuard** (`wireguard-go`) tunnel, NOT comma's VPN stack.
AGNOS runs kernel 4.9 which has **no** `wireguard` module (the wireguard-go
"kernel support available" banner is misleading — ignore it), so tunneling
runs entirely in userspace over `/dev/net/tun`.

- Client address on the VPN: `10.6.0.11/32`
- Server: home router, WireGuard listens on `89.168.73.114:51820` (VPS UDP
  relay forwards to it), pubkey
  `2l3/2npiqro6UVeBdzht7osCPQDuGI4aUJbnXi+59Uo=`
- Split-tunnel: **only** home LAN + VPN subnet go through the tunnel

Tunnel path:
`comma 3X (10.6.0.11) → VPS UDP relay 89.168.73.114:51820 → home router (WG server) → home LAN`
The router routes only `192.168.1.0/24` + `10.6.0.0/24`; it does NOT NAT
tunnel traffic out to the WAN.

## 2. Directory layout (`/data/wgs/`)

```
/data/wgs/
├── boot.lock                 # flock target for boot_wg.sh
├── boot.log                  # boot_wg.sh log (append)
├── boot_wg.sh                # boot-time bring-up (flock + wifi + NTP waits)
├── manual_up.sh              # manual bring-up (destructive re-init)
├── noop_iptables.sh          # (one-time setup helper) stubs iptables-restore
├── setup2.sh                 # (one-time setup helper) builds bin/ symlinks
├── update_conf.sh            # (one-time setup helper) writes wgs_client.conf
├── bin/                      # PATH shim dir used by all scripts
│   ├── ip -> /usr/sbin/ip
│   ├── iptables -> /usr/sbin/iptables-legacy
│   ├── ip6tables -> /usr/sbin/ip6tables-legacy
│   ├── iptables-restore      # NOOP stub (see §5)
│   ├── ip6tables-restore     # NOOP stub (see §5)
│   ├── resolvconf -> /usr/sbin/resolvconf
│   ├── sysctl -> /usr/sbin/sysctl
│   ├── wg -> /data/wgs/root/usr/bin/wg
│   ├── wg-quick -> /data/wgs/root/usr/bin/wg-quick
│   └── wireguard-go -> /data/wgs/root/usr/bin/wireguard-go
├── etc/                      # 0700, secrets
│   ├── wgs_client.wg.conf    # raw wg setconf format (what boot_wg.sh loads)
│   └── wgs_client.conf       # wg-quick format (reference; Address line)
├── root/usr/bin/             # extracted binaries (from the .deb files)
│   ├── wg
│   ├── wg-quick
│   └── wireguard-go
├── backup_2026-09-13/        # pre-split-tunnel backup of scripts + confs
├── wireguard-go_0.0.20230223-1ubuntu0.24.04.2_arm64.deb   # installer source
└── wireguard-tools_1.0.20210914-1ubuntu4_arm64.deb        # installer source
```

## 3. Boot integration (`/data/continue.sh`)

comma's init runs `/usr/comma/comma.sh` (PID 1 → init → tmux session `comma`
→ `comma.sh`). `comma.sh` execs `/data/continue.sh` when it exists — this is
comma's standard "user took over the boot" hook. Our file:

```bash
#!/usr/bin/env bash

( sudo /data/wgs/boot_wg.sh & )

cd /data/openpilot
exec ./launch_openpilot.sh
```

Notes:
- The WG bring-up is backgrounded `( ... & )` so boot proceeds immediately;
  boot_wg.sh does its own waiting (below) before touching the network.
- `sudo` works for the `comma` user without password (AGNOS default).

## 4. Config files

### `etc/wgs_client.wg.conf` (raw `wg setconf` format — this is what runs)

```ini
[Interface]
PrivateKey = <REDACTED>

[Peer]
PublicKey = 2l3/2npiqro6UVeBdzht7osCPQDuGI4aUJbnXi+59Uo=
PresharedKey = <REDACTED>
AllowedIPs = 192.168.1.0/24, 10.6.0.0/24
Endpoint = 89.168.73.114:51820
PersistentKeepalive = 25
```

### `etc/wgs_client.conf` (wg-quick format — reference only, not used at boot)

Same, plus `Address = 10.6.0.11/32` under `[Interface]` (wg-quick style adds
the address itself; the boot script adds it manually instead).

**Critical:** `AllowedIPs` MUST stay the split-tunnel pair
`192.168.1.0/24, 10.6.0.0/24`. Do NOT use `0.0.0.0/0` (see §6, Bug).

## 5. Scripts

### `boot_wg.sh` (full source)

```bash
#!/usr/bin/env bash
set -u
export PATH=/data/wgs/bin:/bin:/usr/bin

LOCKFILE=/data/wgs/boot.lock
exec 9>"$LOCKFILE"
flock -n 9 || exit 0

CONF=/data/wgs/etc/wgs_client.wg.conf
ENDPOINT_IP=89.168.73.114
LOG=/data/wgs/boot.log

log() { echo "$(date '+%F %T') $*" >> "$LOG"; }

if ip link show wgs_client &>/dev/null; then
  log "wgs_client already up, skipping"
  exit 0
fi

# wait for real internet route (wifi association) before touching anything
REAL_GW=""
REAL_DEV=""
for i in $(seq 1 30); do
  REAL_GW=$(ip route show table main | awk '/^default/{print $3; exit}')
  REAL_DEV=$(ip route show table main | awk '/^default/{print $5; exit}')
  [ -n "$REAL_GW" ] && [ -n "$REAL_DEV" ] && break
  sleep 2
done

if [ -z "$REAL_GW" ]; then
  log "no default route after waiting, giving up"
  exit 1
fi

# wait for clock to sync via NTP over the REAL route before bringing up the
# tunnel -- this device has no battery-backed RTC and boots with a stale
# clock, and WireGuard rejects handshakes with a timestamp older than the
# last one the server saw from us.
for i in $(seq 1 30); do
  synced=$(timedatectl show -p NTPSynchronized --value 2>/dev/null)
  [ "$synced" = "yes" ] && break
  sleep 2
done
log "clock sync status: $(timedatectl show -p NTPSynchronized --value 2>/dev/null), date: $(date)"

# SPLIT TUNNEL: only the home LAN (192.168.1.0/24) and the VPN subnet
# (10.6.0.0/24) go through the tunnel. Everything else -- including the
# VPS/MQTT endpoint 89.168.73.114, DNS, and all internet traffic -- stays on
# the real wlan0 default route. This is what fixes mqttd reaching
# mqtt.hendrikgroove.de:1884 while the tunnel is up.
log "bringing up split-tunnel via $REAL_GW dev $REAL_DEV"
{
  wireguard-go wgs_client
  sleep 1
  wg setconf wgs_client "$CONF"
  ip -4 address add 10.6.0.11/32 dev wgs_client
  ip link set mtu 1420 up dev wgs_client

  # pin the VPN server's own address to the real interface so the tunnel's
  # own encrypted packets don't try to route through itself.
  ip route replace "$ENDPOINT_IP/32" via "$REAL_GW" dev "$REAL_DEV"

  # split-tunnel: route only the LAN + VPN subnet through the tunnel.
  # default stays on wlan0 (set high metric so it's unambiguous).
  ip route replace 10.6.0.0/24 dev wgs_client metric 1000
  ip route replace 192.168.1.0/24 dev wgs_client metric 1000

  # DO NOT push DNS through the tunnel: leaving DNS on the real interface is
  # what lets hostname resolution (and mqttd) work. Strip any stale entry.
  resolvconf -d wgs_client 2>/dev/null || true
} >> "$LOG" 2>&1

log "tunnel setup finished (split-tunnel)"
```

### `manual_up.sh` (manual bring-up, full source)

```bash
#!/usr/bin/env bash
set -e
export PATH=/data/wgs/bin:/bin:/usr/bin

# clean slate
ip link delete wgs_client 2>/dev/null || true
ip route del 89.168.73.114/32 2>/dev/null || true

REAL_GW=$(ip route show table main | awk '/^default/{print $3; exit}')
REAL_DEV=$(ip route show table main | awk '/^default/{print $5; exit}')
echo "real gateway: $REAL_GW via $REAL_DEV"

wireguard-go wgs_client
sleep 1
wg setconf wgs_client /data/wgs/etc/wgs_client.wg.conf
ip -4 address add 10.6.0.11/32 dev wgs_client
ip link set mtu 1420 up dev wgs_client

# pin the VPN server's own address to the real interface so tunnel traffic
# can't loop back into itself
ip route add 89.168.73.114/32 via "$REAL_GW" dev "$REAL_DEV"

# SPLIT TUNNEL: only LAN + VPN subnet go through the tunnel. Default route
# stays on wlan0 so internet traffic, DNS, and MQTT (mqtt.hendrikgroove.de ->
# 89.168.73.114 -> 89.168.73.114:1884) reach the broker directly instead of
# dying in the tunnel.
ip route replace 10.6.0.0/24 dev wgs_client metric 1000
ip route replace 192.168.1.0/24 dev wgs_client metric 1000

# keep DNS on the real interface -- do not push nameserver 10.6.0.1
resolvconf -d wgs_client 2>/dev/null || true

echo "--- done (split-tunnel) ---"
```

### Resulting route table (when up)

```
89.168.73.114/32  via <real-gw>  dev wlan0        # endpoint pin (host route)
10.6.0.0/24       dev wgs_client  metric 1000     # VPN subnet via tunnel
192.168.1.0/24    dev wgs_client  metric 1000     # home LAN via tunnel
default           via <real-gw>   dev wlan0       # UNTOUCHED
```

## 6. The key gotchas (all bit us at least once)

1. **`wg` is not in sudo's PATH.** Always use the absolute shim path:
   `sudo /data/wgs/bin/wg show`. A bare `sudo wg` "works" but silently does
   nothing useful (`command not found` swallowed by sudo), and route rules can
   look applied while the crypto key is never loaded.

2. **Full-tunnel broke mqttd + DNS (the Sep 13 bug).** With
   `AllowedIPs = 0.0.0.0/0` + `ip route replace default dev wgs_client` +
   pushed DNS `10.6.0.1`:
   - mqttd (broker hardcoded to `mqtt.hendrikgroove.de:1884`, resolved via
     the VPS `89.168.73.114` HAProxy) routed INTO the tunnel and died — the
     broker address itself must stay on the real route.
   - DNS hung entirely (getent blocked).
   Fix = everything in this doc: split-tunnel AllowedIPs, two metric-1000
   subnet routes, default route untouched, no DNS push.

3. **wireguard-go, not kernel WG.** AGNOS kernel is 4.9 — `modprobe wireguard`
   fails (`Module wireguard not found in directory /lib/modules/4.9.103`).
   The wireguard-go "kernel support available" startup banner is boilerplate
   and does NOT mean the module exists. The tunnel runs in userspace over
   `/dev/net/tun`.

4. **No-RTC clock wait is mandatory.** The device boots with a stale clock.
   WireGuard REJECTS handshakes whose timestamp is older than the last one
   the server recorded. `boot_wg.sh` therefore blocks (up to 60 s) on
   `timedatectl NTPSynchronized=yes` over the REAL route before bringing the
   tunnel up. Skipping this = tunnel silently never handshakes after reboot.

5. **Endpoint pin route.** `89.168.73.114/32 via <real-gw> dev <real-dev>`
   must exist or the tunnel's own encrypted packets can loop back into
   `wgs_client` itself.

6. **Roaming works by itself.** The pinned endpoint route is flushed by the
   kernel when wlan0 loses its address (hotspot → home wifi or vice versa);
   wireguard-go keeps the UDP socket bound and re-handshakes through whatever
   default route exists next. No script restart needed on network change.
   Known flake: hotspot SSID vanishing = zero connectivity (not a tunnel
   fault).

7. **No cellular on this device.** On the road it lives on a phone hotspot
   only; the tunnel is the ONLY remote-access path once off the home LAN.

8. **`resolvconf -d wgs_client` at bring-up** strips any stale DNS entry from
   earlier experiments. If a `nameserver 10.6.0.1` ever reappears in
   resolv.conf, DNS will hang again — check there first when "internet is
   broken but tunnel is up".

## 7. Verification / health checks

```bash
# tunnel up + recent handshake?
sudo /data/wgs/bin/wg show          # look at "latest handshake"

# routes correct?
ip route | grep -E "wgs|89.168"

# MQTT broker connected? (mqttd stdout goes to tmux pts, not a log)
ss -tnp | grep 1884

# DNS sane?
grep nameserver /etc/resolv.conf    # must NOT be 10.6.0.1

# boot-time behavior
tail -20 /data/wgs/boot.log
```

## 8. Porting to another comma 3X (checklist)

1. Copy `/data/wgs/` to the new device (binaries, `bin/` shims, scripts).
   The two `.deb` files are the installer sources; `root/usr/bin/` holds the
   extracted binaries.
2. Create the new device's WG keys with the server admin and write
   `/data/wgs/etc/wgs_client.wg.conf` with **that device's** PrivateKey,
   its tunnel IP (`Address` is added by the script — currently hardcoded
   `10.6.0.11/32` in `boot_wg.sh` + `manual_up.sh`, edit both for a new IP),
   and the same split-tunnel `AllowedIPs`.
3. Verify `/data/continue.sh` exists on the new device with the same
   backgrounded `boot_wg.sh` invocation before `launch_openpilot.sh`.
4. Reboot, then check §7: handshake, routes, resolv.conf, MQTT.
5. Router side: add the new peer (PublicKey + tunnel IP) to the home router's
   WG config.

---

*Documented 2026-09-23 from the live Ioniq device. Live-state caveat: at doc
time the tunnel was DOWN (device on home wifi, `wgs_client` interface absent)
— boot_wg.sh only brings it up at boot or via manual_up.sh; it does not
auto-revive a torn-down interface while running.*
