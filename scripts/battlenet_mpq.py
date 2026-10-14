"""Read small, unencrypted resources from Battle.net's local MPQ archive.

Only the legacy tables used by MPQ versions 0/1 are supported. Unsupported
archives and compression methods raise ValueError so artwork can fall back.
"""
import struct
import zlib

MASK = 0xffffffff
MAX_RESOURCE = 1024 * 1024


def crypt_table():
    table = [0] * 0x500
    seed = 0x100001
    for low in range(256):
        for high in range(5):
            seed = (seed * 125 + 3) % 0x2aaaab
            upper = (seed & 0xffff) << 16
            seed = (seed * 125 + 3) % 0x2aaaab
            table[low + high * 256] = upper | (seed & 0xffff)
    return table


CRYPT = crypt_table()


def mpq_hash(name, kind):
    first, second = 0x7fed7fed, 0xeeeeeeee
    for char in name.upper().encode('ascii'):
        first = (CRYPT[(kind << 8) + char] ^ (first + second)) & MASK
        second = (char + first + second + (second << 5) + 3) & MASK
    return first


def decrypt(data, key):
    output = bytearray()
    seed = 0xeeeeeeee
    for (word,) in struct.iter_unpack('<I', data):
        seed = (seed + CRYPT[0x400 + (key & 255)]) & MASK
        plain = (word ^ ((key + seed) & MASK)) & MASK
        output.extend(struct.pack('<I', plain))
        key = (((~key << 21) + 0x11111111) | (key >> 11)) & MASK
        seed = (plain + seed + (seed << 5) + 3) & MASK
    return output


class MPQ:
    def __init__(self, stream):
        self.stream = stream
        stream.seek(0, 2)
        self.size = stream.tell()
        signature, header_size, _, version, shift, hp, bp, hc, bc = struct.unpack('<4sIIHHIIII', self.read(0, 32))
        if signature != b'MPQ\x1a' or version > 1 or header_size < 32 or shift > 12:
            raise ValueError('unsupported MPQ header')
        if version == 1:
            if header_size < 44 or any(self.read(32, 12)):
                raise ValueError('unsupported extended MPQ tables')
        if not 1 <= hc <= 65536 or not 1 <= bc <= 65536:
            raise ValueError('invalid MPQ table size')
        self.hashes = decrypt(self.read(hp, hc * 16), mpq_hash('(hash table)', 3))
        self.blocks = decrypt(self.read(bp, bc * 16), mpq_hash('(block table)', 3))
        self.hash_count, self.block_count = hc, bc
        self.sector_size = 512 << shift

    def read(self, offset, size):
        if offset < 0 or size < 0 or size > MAX_RESOURCE or offset + size > self.size:
            raise ValueError('invalid MPQ offset')
        self.stream.seek(offset)
        data = self.stream.read(size)
        if len(data) != size:
            raise ValueError('truncated MPQ')
        return data

    @staticmethod
    def unpack(data, size):
        if len(data) == size:
            return data
        if not data or data[0] != 2:
            raise ValueError('unsupported MPQ compression')
        decoder = zlib.decompressobj()
        try:
            output = decoder.decompress(data[1:], size + 1)
        except zlib.error as error:
            raise ValueError('invalid compressed MPQ resource') from error
        if len(output) != size or not decoder.eof or decoder.unused_data:
            raise ValueError('invalid compressed MPQ resource')
        return output

    def resource(self, name):
        first, second = mpq_hash(name, 1), mpq_hash(name, 2)
        start = mpq_hash(name, 0) % self.hash_count
        index = None
        for n in range(self.hash_count):
            a, b, _, _, block = struct.unpack_from('<IIHHI', self.hashes, ((start + n) % self.hash_count) * 16)
            if block == MASK:
                break
            if a == first and b == second and block != 0xfffffffe:
                index = block
                break
        if index is None:
            raise KeyError(name)
        if index >= self.block_count:
            raise ValueError('invalid MPQ block')
        offset, packed, size, flags = struct.unpack_from('<IIII', self.blocks, index * 16)
        # File exists; permit only compressed/single-unit flags in addition.
        if not flags & 0x80000000 or flags & ~0x85000200 or not 0 < size <= MAX_RESOURCE:
            raise ValueError('unsupported MPQ resource flags or size')
        data = self.read(offset, packed)
        if not flags & 0x200:
            if len(data) != size:
                raise ValueError('invalid MPQ resource length')
            return data
        if flags & 0x1000000:
            return self.unpack(data, size)
        count = (size + self.sector_size - 1) // self.sector_size
        offset_count = count + (2 if flags & 0x4000000 else 1)
        table_size = offset_count * 4
        if len(data) < table_size:
            raise ValueError('truncated MPQ sectors')
        offsets = struct.unpack_from('<' + 'I' * offset_count, data)
        if offsets[0] < table_size or offsets[-1] != len(data) or offsets[count] > offsets[-1] or any(a >= b for a, b in zip(offsets[:count], offsets[1:count + 1])):
            raise ValueError('invalid MPQ sectors')
        return b''.join(self.unpack(data[offsets[i]:offsets[i + 1]], min(self.sector_size, size - i * self.sector_size)) for i in range(count))
