"""Localhost-only passive MLBB live chat viewer package."""

from .battle import BattleTickProcessor, Lzw16Decoder, extract_ticks_from_subframe, parse_0175_subframes
from .kcp import KcpSegment, KcpStreamReassembler, parse_kcp_datagram
from .pcap_reader import IncrementalPcapReader, InvalidPcapMagicError, UdpPacket
from .protocol import (
    extract_events_from_struct_list,
    extract_events_from_tick_bytes,
    lz4_decompress_raw,
    parse_chat_body,
    parse_mlbb_struct,
    read_varint,
)

__all__ = [
    "BattleTickProcessor",
    "IncrementalPcapReader",
    "InvalidPcapMagicError",
    "KcpSegment",
    "KcpStreamReassembler",
    "Lzw16Decoder",
    "UdpPacket",
    "extract_events_from_struct_list",
    "extract_events_from_tick_bytes",
    "extract_ticks_from_subframe",
    "lz4_decompress_raw",
    "parse_0175_subframes",
    "parse_chat_body",
    "parse_kcp_datagram",
    "parse_mlbb_struct",
    "read_varint",
]
