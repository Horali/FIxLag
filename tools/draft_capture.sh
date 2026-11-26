#!/system/bin/sh
# Draft-pick endpoint capture for MLBB.
#
# Runs as root through the command daemon (see docs/handoff.md §3), not from
# adb shell -- adb shell has no root on this device.
#
# Usage:
#   nohup sh /sdcard/draft_capture.sh <seconds> <label> [snaplen] [filter] \
#       >/dev/null 2>&1 &
#
# snaplen defaults to 96 (headers only, enough to attribute flows). Pass 1500
# when the question needs the payload itself -- chat text, protocol shape.
# filter defaults to "udp". Pass "udp or tcp" when the traffic of interest may
# ride a TCP connection (in-match chat may use the lobby TCP link).
#
# Writes, under /sdcard:
#   draft_<label>.pcap   raw capture, SLL2 link type (interface per packet)
#   draft_<label>.log    start/end epoch, addresses, routes, tcpdump summary
#   draft_<label>.done   sentinel, touched only after tcpdump exits
#
# The pcap file grows while tcpdump runs. classify is truncation-safe, so a
# partial file can be read at draft pick before the capture has ended.

SECS="${1:-1500}"
LABEL="${2:-draft}"
SNAP="${3:-96}"
FILTER="${4:-udp}"

PCAP="/sdcard/draft_${LABEL}.pcap"
LOG="/sdcard/draft_${LABEL}.log"
DONE="/sdcard/draft_${LABEL}.done"

rm -f "$PCAP" "$LOG" "$DONE"

{
  echo "LABEL $LABEL"
  echo "START $(date +%s)"
  echo "SNAPLEN $SNAP"
  echo "FILTER $FILTER"
  echo "--- ip -o addr ---"
  ip -o addr 2>/dev/null
  echo "--- ip route ---"
  ip route 2>/dev/null
} > "$LOG" 2>&1

# All UDP. No port filter: the match server is usually on 5xxx, but a
# concurrent relay was once seen on 10011 (plan.md §5.8), so filtering by port
# risks dropping the flow we are looking for.
timeout "$SECS" tcpdump -i any -n -s "$SNAP" -U -w "$PCAP" "$FILTER" >> "$LOG" 2>&1
RC=$?

echo "END $(date +%s)" >> "$LOG"
echo "RC $RC" >> "$LOG"
echo "SIZE $(wc -c < "$PCAP" 2>/dev/null)" >> "$LOG"
touch "$DONE"

exit 0
