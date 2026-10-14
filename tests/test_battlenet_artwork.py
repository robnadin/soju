"""Synthetic archive fixtures; no Blizzard artwork is stored in this repository."""
import io
from pathlib import Path
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch
import zlib

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'scripts'))
from battlenet_mpq import CRYPT, MASK, MPQ, mpq_hash
from game_artwork import BNET_LOGOS, battlenet_client_icon, svg_logo

SVG = b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 48 48"><path d="M0 0h48v48H0z"/></svg>'


def encrypt(data, key):
    result = bytearray()
    seed = 0xeeeeeeee
    for (plain,) in struct.iter_unpack('<I', data):
        seed = (seed + CRYPT[0x400 + (key & 255)]) & MASK
        result.extend(struct.pack('<I', plain ^ ((key + seed) & MASK)))
        key = (((~key << 21) + 0x11111111) | (key >> 11)) & MASK
        seed = (plain + seed + (seed << 5) + 3) & MASK
    return result


def archive(name, data=SVG, compressed=True, sectors=False, flags=0, version=0):
    hashes = bytearray(b'\xff' * 16 * 8)
    at = mpq_hash(name, 0) % 8
    struct.pack_into('<IIHHI', hashes, at * 16, mpq_hash(name, 1), mpq_hash(name, 2), 0, 0, 0)
    if compressed:
        if sectors:
            chunks = [data[i:i + 512] for i in range(0, len(data), 512)]
            packed = [b'\x02' + zlib.compress(chunk) for chunk in chunks]
            packed = [a if len(a) < len(b) else b for a, b in zip(packed, chunks)]
            offsets = [(len(chunks) + 1) * 4]
            for chunk in packed:
                offsets.append(offsets[-1] + len(chunk))
            payload = struct.pack('<' + 'I' * len(offsets), *offsets) + b''.join(packed)
        else:
            payload = b'\x02' + zlib.compress(data)
        flags |= 0x200
    else:
        payload = data
    if not sectors:
        flags |= 0x1000000
    header = struct.pack('<4sIIHHIIII', b'MPQ\x1a', 32, 176 + len(payload), version, 0, 32, 160, 8, 1)
    blocks = struct.pack('<IIII', 176, len(payload), len(data), flags | 0x80000000)
    return header + encrypt(hashes, mpq_hash('(hash table)', 3)) + encrypt(blocks, mpq_hash('(block table)', 3)) + payload


class MPQTests(unittest.TestCase):
    def test_compressed_and_uncompressed_resources(self):
        for compressed in (True, False):
            with self.subTest(compressed=compressed):
                reader = MPQ(io.BytesIO(archive('icon.svg', compressed=compressed)))
                self.assertEqual(reader.resource('ICON.SVG'), SVG)
                with self.assertRaises(KeyError):
                    reader.resource('missing.svg')

    def test_sector_compression(self):
        data = SVG * 30
        self.assertEqual(MPQ(io.BytesIO(archive('icon.svg', data, sectors=True))).resource('icon.svg'), data)

    def test_invalid_headers_and_tables(self):
        valid = archive('icon.svg')
        for data in (b'', valid[:40], b'BAD!' + valid[4:], archive('icon.svg', version=2)):
            with self.subTest(data=data[:32]):
                with self.assertRaises((ValueError, struct.error)):
                    MPQ(io.BytesIO(data))

    def test_encrypted_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            MPQ(io.BytesIO(archive('icon.svg', flags=0x10000))).resource('icon.svg')

    def test_truncated_resource_is_rejected(self):
        with self.assertRaises(ValueError):
            MPQ(io.BytesIO(archive('icon.svg')[:-1])).resource('icon.svg')

    def test_decompression_is_bounded_and_validated(self):
        for data, size in [(b'\x02' + zlib.compress(b'x' * 100000), 2), (b'\x02bad', 20), (b'\x10bad', 20)]:
            with self.subTest(size=size):
                with self.assertRaises(ValueError):
                    MPQ.unpack(data, size)


class ClientArtworkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'Battle.net'
        self.cache = Path(self.temp.name) / 'cache'

    def put(self, uid='w1', version=9, data=SVG):
        path = self.root / ('Battle.net.' + str(version)) / 'Battle.net.mpq'
        path.parent.mkdir(parents=True, exist_ok=True)
        name = 'resources\\js\\phoenix_home\\icons\\' + BNET_LOGOS[uid] + '.svg'
        path.write_bytes(archive(name, data))
        return path

    def test_classic_and_remastered_warcraft_mapping(self):
        for uid, logo in [('w1', 'warcraft'), ('w1r', 'warcraft-remastered'), ('w2bn', 'warcraft-II'), ('w2r', 'warcraft-II-remastered')]:
            with self.subTest(uid=uid):
                self.assertEqual(BNET_LOGOS[uid], logo)
                self.put(uid)
                output = battlenet_client_icon(self.root, uid.upper(), self.cache)
                self.assertEqual(Path(output).read_bytes(), SVG)

    def test_agent_warcraft_ids_resolve_client_svg_resources(self):
        for uid, filename in [('w2', 'warcraft-II.svg'),
                              ('gryphon', 'warcraft-arclight-rumble.svg')]:
            with self.subTest(uid=uid):
                path = self.root / 'Battle.net.10' / 'Battle.net.mpq'
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(archive('resources\\js\\phoenix_home\\icons\\' + filename))
                output = battlenet_client_icon(self.root, uid.upper(), self.cache)
                self.assertIsNotNone(output)
                self.assertEqual(Path(output).suffix, '.svg')
                self.assertEqual(Path(output).read_bytes(), SVG)

    def test_newest_client_is_selected_numerically(self):
        self.put(version=9)
        newer = SVG.replace(b'M0', b'M1')
        self.put(version=10, data=newer)
        output = battlenet_client_icon(self.root, 'w1', self.cache)
        self.assertEqual(Path(output).read_bytes(), newer)

    def test_cached_artwork_does_not_reopen_archive(self):
        self.put()
        output = battlenet_client_icon(self.root, 'w1', self.cache)
        with patch('game_artwork.MPQ', side_effect=AssertionError('cache miss')):
            self.assertEqual(battlenet_client_icon(self.root, 'w1', self.cache), output)

    def test_archive_update_invalidates_cache(self):
        path = self.put()
        first = battlenet_client_icon(self.root, 'w1', self.cache)
        newer = SVG.replace(b'M0', b'M123')
        self.put(data=newer)
        second = battlenet_client_icon(self.root, 'w1', self.cache)
        self.assertNotEqual(first, second)
        self.assertEqual(Path(second).read_bytes(), newer)

    def test_corrupt_newest_client_falls_back_to_older_archive(self):
        self.put(version=9)
        self.put(version=10).write_bytes(b'broken')
        self.assertIsNotNone(battlenet_client_icon(self.root, 'w1', self.cache))

    def test_missing_unknown_and_missing_resource_return_none(self):
        self.assertIsNone(battlenet_client_icon(self.root, 'w1', self.cache))
        self.put()
        self.assertIsNone(battlenet_client_icon(self.root, 'future', self.cache))
        self.assertIsNone(battlenet_client_icon(self.root, 'w2bn', self.cache))

    def test_unsafe_and_invalid_svg_return_none(self):
        for data in [b'not svg', b'<!DOCTYPE svg><svg/>', b'<svg xmlns="http://www.w3.org/2000/svg"><script/></svg>', b'<svg xmlns="http://www.w3.org/2000/svg"><use href="https://example.com/icon"/></svg>']:
            with self.subTest(data=data):
                self.put(data=data)
                self.assertIsNone(battlenet_client_icon(self.root, 'w1', self.cache))

    def test_local_gradient_references_are_supported(self):
        data = SVG.replace(b'<path ', b'<path fill="url(\'#gradient\')" ')
        self.assertEqual(svg_logo(data), data)

    def test_unwritable_cache_returns_none(self):
        self.put()
        self.cache.write_text('not a directory')
        self.assertIsNone(battlenet_client_icon(self.root, 'w1', self.cache))
