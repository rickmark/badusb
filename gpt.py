"""Simple GPT parsing"""

import collections
import struct
import uuid
from io import BytesIO

# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_table_header_.28LBA_1.29
GPT_HEADER_FORMAT = """
8s signature
4s revision
L header_size
L crc32
4x _
Q current_lba
Q backup_lba
Q first_usable_lba
Q last_usable_lba
16s disk_guid
Q part_entry_start_lba
L num_part_entries
L part_entry_size
L crc32_part_array
"""

# http://en.wikipedia.org/wiki/GUID_Partition_Table#Partition_entries_.28LBA_2.E2.80.9333.29
GPT_PARTITION_FORMAT = """
16s type
16s unique
Q first_lba
Q last_lba
Q flags
72s name
"""

READS = []


def _make_fmt(name, format, extras=[]):
    type_and_name = [l.split(None, 1) for l in format.strip().splitlines()]
    fmt = ''.join(t for (t,n) in type_and_name)
    fmt = '<'+fmt
    tupletype = collections.namedtuple(name, [n for (t,n) in type_and_name if n!='_']+extras)
    return (fmt, tupletype)


def get_partition(byte):
    if not READS:
        return "N/A"
    for part in READS[-1].values():
        if part.first_byte <= byte < part.last_byte:
            return part.name
    return "N/A"

class GPTError(Exception):
    pass


def read_header(fp, lba_size=512):
    fp.seek(0, 0)
    # skip MBR
    fp.seek(1*lba_size, 0)
    fmt, GPTHeader = _make_fmt('GPTHeader', GPT_HEADER_FORMAT)
    data = fp.read(struct.calcsize(fmt))
    print("Len data: %i" % len(data))
    header = GPTHeader._make(struct.unpack(fmt, data))
    if header.signature != b'EFI PART':
        raise GPTError('Bad signature: %r' % header.signature)
    if header.revision != b'\x00\x00\x01\x00':
        raise GPTError('Bad revision: %r' % header.revision)
    if header.header_size < 92:
        raise GPTError('Bad header size: %r' % header.header_size)
    # TODO check crc32
    header = header._replace(
        disk_guid=str(uuid.UUID(bytes_le=header.disk_guid)),
        )
    return header


class Partition(object):
    def __init__(self, name, flags, first_lba, last_lba, unique, type):
        self.name = name
        self.flags = flags
        self.first_byte = 512 * first_lba
        self.last_byte = 512 * last_lba
        self.unique = unique
        self.type = type

    @classmethod
    def from_gpt(cls, part):
        return cls(name=part.name, flags=part.flags, first_lba=part.first_lba, last_lba=part.last_lba,
                   unique=part.unique, type=part.type)

    def contains_byte(self, idx):
        return (512 * self.first_byte) <= idx < (512 * self.last_byte)

    def __repr__(self):
        return "Partition(%s):%iMB-%iMB:" % (self.name, self.first_byte >> 20, self.last_byte >> 20)


def read_partitions(fp, header, lba_size=512):
    fp.seek(header.part_entry_start_lba * lba_size)
    fmt, GPTPartition = _make_fmt('GPTPartition', GPT_PARTITION_FORMAT, extras=['index'])
    for idx in range(1, 1+header.num_part_entries):
        data = fp.read(header.part_entry_size)
        if len(data) < struct.calcsize(fmt):
            break
        part = GPTPartition._make(struct.unpack(fmt, data) + (idx,))
        if part.type == 16 * b'\0':
            continue
        part = part._replace(
            type=str(uuid.UUID(bytes_le=part.type)),
            unique=str(uuid.UUID(bytes_le=part.unique)),
            # do C-style string termination; otherwise you'll see a
            # long row of NILs for most names
            name=part.name.decode('utf-16').split('\0', 1)[0],
            )
        yield part


def parse(data, offset):
    if offset < (1 << 16):
        print("GPT parser received %i bytes at offset %i" % (len(data), offset))
    if offset != 0:
        return
    fp = BytesIO(data)
    header = read_header(fp)
    parts = [i for i in read_partitions(fp, header)]
    READS.append({i.name: Partition.from_gpt(i) for i in parts})
    print("Parsed GPT:\n  " + '\n  '.join([("%s: %s" % (k, repr(v))) for k, v in READS[-1].items()]))


def parse_gpt(func):
    def wrapper(*args, **kwargs):
        _kwargs = dict(zip(func.__code__.co_varnames, args))
        _kwargs.update(kwargs)
        data = func(*args, **kwargs)
        parse(data, _kwargs['offset'])
        return data
    return wrapper
