import argparse
import csv
import enum
import struct

from collections import namedtuple
from typing import Union


class MsgType(enum.IntEnum):
    SYS = 0x00
    CMD = 0x40
    INFO = 0x80
    DATA = 0xC0


class MsgSize(enum.IntEnum):
    B1 = 0 << 3
    B2 = 1 << 3
    B4 = 2 << 3
    B8 = 3 << 3
    B16 = 4 << 3
    B32 = 5 << 3

    @property
    def real_size(self) -> int:
        return 1 << (self >> 3)


class Sys(enum.IntEnum):
    SYNC = 0
    NACK = 2
    ACK = 4
    ESC = 6


class Cmd(enum.IntEnum):
    TYPE = 0
    MODES = 1
    SPEED = 2
    SELECT = 3
    WRITE = 4
    UNK1 = 5,
    EXT_MODE = 6
    VERSION = 7


class Mode(enum.IntEnum):
    M0 = 0
    M1 = 1
    M2 = 2
    M3 = 3
    M4 = 4
    M5 = 5
    M6 = 6
    M7 = 7


class Info(enum.IntEnum):
    NAME = 0
    RAW = 1
    PCT = 2
    SI = 3
    UNITS = 4
    MAPPING = 5
    MODE_COMBOS = 6
    MOTOR_BIAS = 7
    CAPABILITY = 8
    UNKNOWN_9 = 9
    UNKNOWN_10 = 10
    UNKNOWN_11 = 11
    UNKNOWN_12 = 12
    FORMAT = 0x80


MODE_PLUS_8_FLAG = 0x20


class DataType(enum.IntEnum):
    DATA8 = 0
    DATA16 = 1
    DATA32 = 2
    FLOAT = 3


class TypeId(enum.IntEnum):
    EV3_COLOR_SENSOR = 29
    EV3_ULTRASONIC_SENSOR = 30
    EV3_GYRO_SENSOR = 32
    EV3_IR_SENSOR = 33
    WEDO2_TILT_SENSOR = 34
    WEDO2_MOTION_SENSOR = 35
    WEDO2_GENERIC_SENSOR = 36
    COLOR_DIST_SENSOR = 37
    INTERACTIVE_MOTOR = 38
    MOVE_HUB_MOTOR = 39
    CPLUS_L_MOTOR = 46
    CPLUS_XL_MOTOR = 47
    SPIKE_M_MOTOR = 48
    SPIKE_L_MOTOR = 49
    SPIKE_COLOR_SENSOR = 61
    SPIKE_FORCE_SENSOR = 63


class Mappings(enum.IntFlag):
    NULL = 1 << 7
    V2_0 = 1 << 6
    ABS = 1 << 4
    REL = 1 << 3
    DIS = 1 << 2
    NONE = 0


class ModeCombos(enum.IntFlag):
    M0 = 1 << 0
    M1 = 1 << 1
    M2 = 1 << 2
    M3 = 1 << 3
    M4 = 1 << 4
    M5 = 1 << 5
    M6 = 1 << 6
    M7 = 1 << 7
    M8 = 1 << 8
    M9 = 1 << 9
    M10 = 1 << 10
    M11 = 1 << 11
    M12 = 1 < 120
    M13 = 1 < 130
    M14 = 1 < 140
    M15 = 1 < 150


def parse_header(value: int) -> (MsgType, MsgSize, Union[Sys, Cmd, int]):
    msg_type = MsgType(value & 0xC0)
    msg_size = MsgSize(value & 0x38)
    msg = value & 0x7

    if msg_type == MsgType.SYS:
        msg = Sys(msg)
    elif msg_type == MsgType.CMD:
        msg = Cmd(msg)
    else:
        msg = Mode(msg)

    return msg_type, msg_size, msg


parser = argparse.ArgumentParser("LPF2 UART Protocol Analyzer")
parser.add_argument('file',
                    metavar='<file>',
                    type=argparse.FileType('r'),
                    help='.csv file containing captured data')
parser.add_argument('-g',
                    '--group',
                    metavar='<name>',
                    default=None,
                    help='Group to print')
args = parser.parse_args()

Bytecode = namedtuple('Bytecode', ['value', 'timestamp'])

data = {}

for r in csv.DictReader(args.file):
    if 'framing error' in r[' Decoded Protocol Result']:
        continue
    data.setdefault(r[' Analyzer Name'], []).append(
        Bytecode(int(r[' Decoded Protocol Result'], 16), r['Time [s]']))

for k, v in data.items():
    if args.group is not None and k != args.group:
        continue
    print('Group:', k)

    values = iter(v)
    ext_mode = 0
    while True:
        try:
            header = next(values).value
            checksum = header
            try:
                typ, size, msg = parse_header(header)
            except ValueError:
                print(f'Skipping header 0x{header:02X}')
                continue
            print(typ, size, msg, f'(0x{header:02X})')

            if typ == MsgType.SYS:
                continue

            if typ == MsgType.INFO:
                flags = next(values).value
                mode_plus_8 = bool(flags & MODE_PLUS_8_FLAG)
                info = Info(flags & ~MODE_PLUS_8_FLAG)
                checksum ^= flags
                print('INFO:', info, 'mode+8:', mode_plus_8,
                      f'(0x{flags:02X})')

            payload = bytearray()
            for _ in range(size.real_size):
                b = next(values).value
                payload.append(b)
                checksum ^= b
            print('size', size.real_size)
            checksum ^= next(values).value

            print(f'Checksum: {"OK" if checksum == 0xFF else "BAD"}')

            if typ == MsgType.CMD:
                if msg == Cmd.TYPE:
                    type_id = TypeId(payload[0])
                    print(f'TYPE:', type_id, f'(0x{type_id:02X})')
                elif msg == Cmd.MODES:
                    if size == MsgSize.B4:
                        num_modes = payload[2]
                        num_views = payload[3]
                    elif size == MsgSize.B2:
                        num_modes = payload[0]
                        num_views = payload[1]
                    elif size == MsgSize.B1:
                        num_modes = num_views = payload[0]
                    print('MODES:', num_modes, 'views:', num_views)
                elif msg == Cmd.SPEED:
                    if len(payload) == 4:
                        speed, = struct.unpack('<I', payload)
                        print('SPEED:', speed)
                    else:
                        speed, unknown = struct.unpack('<II', payload)
                        print('SPEED:', speed, 'unknown', unknown)
                elif msg == Cmd.SELECT:
                    mode = payload[0]
                    print('mode:', mode)
                elif msg == Cmd.WRITE:
                    if (payload[0] & 0x20) == 0x20:
                        num_modes = payload[0] & 0x0F
                        combo_index = payload[1]
                        mode_dataset = [(v >> 4, v & 0xF)
                                        for v in payload[2:2 + num_modes]]
                        print('WRITE:', 'setup combo', 'num modes:', num_modes,
                              'combo index', combo_index,
                              'mode/dataset pairs:', mode_dataset)
                    else:
                        print('WRITE:',
                              ','.join(f'0x{c:02X}' for c in payload))
                elif msg == Cmd.EXT_MODE:
                    ext_mode = payload[0]
                    print('EXT_MODE:', ext_mode)
                elif msg == Cmd.VERSION:
                    fw_ver, hw_ver = struct.unpack('<II', payload)
                    print('VERSION:', hex(fw_ver), 'HW:', hex(hw_ver))
                else:
                    print('unhandled CMD', msg, payload)
            elif typ == MsgType.INFO:
                if info == Info.NAME:
                    if len(payload) > 11:
                        name = payload[:6].decode().strip('\0')
                        flags = payload[6:12]
                        print('NAME:', name, 'flags',
                              [f'0x{v:02X}' for v in flags])
                    else:
                        name = payload.decode().strip('\0')
                        print('NAME:', name)
                elif info == Info.RAW:
                    raw_min, raw_max = struct.unpack('<ff', payload)
                    print('RAW', raw_min, 'to', raw_max)
                elif info == Info.PCT:
                    pct_min, pct_max = struct.unpack('<ff', payload)
                    print('PCT', pct_min, 'to', pct_max)
                elif info == Info.SI:
                    si_min, si_max = struct.unpack('<ff', payload)
                    print('SI', si_min, 'to', si_max)
                elif info == Info.UNITS:
                    units = payload.decode().strip('\0')
                    print('UNITS:', units)
                elif info == Info.MAPPING:
                    in_map = Mappings(payload[0])
                    out_map = Mappings(payload[1])
                    print('MAPPING:', 'in:', in_map, 'out:', out_map)
                elif info == Info.MODE_COMBOS:
                    fmt = 'H' * (len(payload) // 2)
                    combos = struct.unpack('<' + fmt, payload)
                    combos = [ModeCombos(c) for c in combos]
                    print('MODE COMBOS:', len(combos), combos,
                          f"({','.join(f'0x{c:04X}' for c in combos)})")
                elif info == Info.UNKNOWN_9:
                    params = struct.unpack('<iiii', payload)
                    print("UNKNOWN 9:", params)
                elif info == Info.UNKNOWN_10:
                    params = struct.unpack('<iiii', payload)
                    print("UNKNOWN 10:", params)
                elif info == Info.UNKNOWN_12:
                    value, = struct.unpack('<h', payload[:2])
                    print("UNKNOWN 12:", value)
                elif info == Info.FORMAT:
                    num_values = payload[0]
                    data_type = DataType(payload[1])
                    digits = payload[2]
                    decimals = payload[3]
                    print('FORMAT:', num_values, data_type, 'digits:', digits,
                          'decimals:', decimals)
                else:
                    print('unhandled info', info, list(payload))
            elif typ == MsgType.DATA:
                print(f'Data for mode {msg + ext_mode}:', payload)
            else:
                print('unhandled message type', typ, list(payload))

            print()
        except StopIteration:
            break

    print()
