#!/bin/busybox sh
set -eu

fail() {
  echo "SIMFERRET_NETWORK_INFRA_FAILURE kind=$1"
  /bin/busybox poweroff -f
  exit 1
}

fetch_and_check() {
  request_number="$1"
  request_id="$(printf 'request-%06d' "$request_number")"
  response="/tmp/$request_id"
  expected="/tmp/$request_id.expected"
  tftp_errors="/tmp/$request_id.tftp-errors"

  /bin/busybox rm -f "$response" "$expected" "$tftp_errors"
  if ! /bin/busybox tftp -g -r "$request_id" -l "$response" 10.0.2.2 \
    2>"$tftp_errors"; then
    /bin/busybox cat "$tftp_errors"
    fail tftp
  fi
  printf 'request_id=%s\npayload=payload-%06d\n' \
    "$request_id" "$request_number" >"$expected"
  if ! /bin/busybox cmp -s "$expected" "$response"; then
    echo "SIMFERRET_NETWORK_PROPERTY_FAILURE kind=response_mismatch request_id=$request_id"
    /bin/busybox poweroff -f
    exit 1
  fi
  echo "SIMFERRET_NETWORK_REQUEST_OK request_id=$request_id phase=$2"
}

/bin/busybox mount -t proc proc /proc || fail mount_proc
/bin/busybox mount -t sysfs sysfs /sys || fail mount_sysfs
/bin/busybox insmod /modules/mii.ko || fail load_mii
/bin/busybox insmod /modules/8139cp.ko || fail load_8139cp

/bin/busybox ip link set eth0 up || fail link_up
/bin/busybox ip address add 10.0.2.15/24 dev eth0 || fail address
/bin/busybox ip route add default via 10.0.2.2 || fail default_route

driver="$(/bin/busybox readlink /sys/class/net/eth0/device/driver || true)"
case "$driver" in
  */8139cp) ;;
  *) fail wrong_driver ;;
esac
echo "SIMFERRET_NETWORK_DRIVER_OK driver=${driver##*/}"

request_count="$(/bin/busybox cat /etc/simferret-request-count)"
request_number=1
while [ "$request_number" -le "$request_count" ]; do
  fetch_and_check "$request_number" before_outage
  request_number=$((request_number + 1))
done

/bin/busybox ip route add prohibit 10.0.2.2/32 || fail install_outage
route="$(/bin/busybox ip route show exact 10.0.2.2/32 || true)"
case "$route" in
  prohibit\ 10.0.2.2*) ;;
  *) fail verify_outage ;;
esac
if ! /bin/outage-probe; then
  fail outage_probe
fi
echo "SIMFERRET_NETWORK_OUTAGE_OK errno=13"

/bin/busybox ip route del prohibit 10.0.2.2/32 || fail remove_outage
route="$(/bin/busybox ip route show exact 10.0.2.2/32 || true)"
case "$route" in
  prohibit\ 10.0.2.2*) fail verify_restoration ;;
esac

request_number=1
while [ "$request_number" -le "$request_count" ]; do
  fetch_and_check "$request_number" after_restoration
  request_number=$((request_number + 1))
done

echo "SIMFERRET_NETWORK_PHASE0_OK version=1 requests=$request_count"
/bin/busybox poweroff -f
