"""Read artwork from local executables and launcher resources; no downloads."""
import hashlib
from pathlib import Path
import struct
import re
import tempfile
import xml.etree.ElementTree as ET
from battlenet_mpq import MPQ


def executable_icon(executable, cache):
    try:
        stat = executable.stat()
        key = hashlib.sha256((str(executable) + str(stat.st_mtime_ns) + str(stat.st_size)).encode()).hexdigest()
        output = Path(cache) / (key + '.ico')
        if output.is_file(): return str(output)
        with executable.open('rb') as stream:
            def read(at, size):
                if at < 0 or size < 0 or size > 8 * 1024 * 1024 or at + size > stat.st_size:
                    raise ValueError('invalid PE offset')
                stream.seek(at); data = stream.read(size)
                if len(data) != size: raise ValueError('truncated executable')
                return data
            def number(at, form='<I'):
                return struct.unpack(form, read(at, struct.calcsize(form)))[0]
            if read(0, 2) != b'MZ': return None
            pe = number(0x3c)
            if read(pe, 4) != b'PE\x00\x00': return None
            sections, optional_size = number(pe + 6, '<H'), number(pe + 20, '<H')
            if not 1 <= sections <= 96: return None
            optional = pe + 24
            magic = number(optional, '<H')
            directory = 112 if magic == 0x20b else 96 if magic == 0x10b else None
            if directory is None or optional_size < directory + 24: return None
            resource_rva = number(optional + directory + 16)
            segments = []
            for i in range(sections):
                section = optional + optional_size + i * 40
                virtual_size, address, raw_size, raw = struct.unpack('<IIII', read(section + 8, 16))
                segments.append((address, raw_size, raw))
            def offset(rva):
                for address, size, raw in segments:
                    if address <= rva < address + size: return raw + rva - address
                raise ValueError('resource outside file sections')
            base = offset(resource_rva)
            def entries(relative):
                named, ids = struct.unpack('<HH', read(base + relative + 12, 4))
                if named + ids > 4096: raise ValueError('too many resources')
                return [struct.unpack('<II', read(base + relative + 16 + i * 8, 8)) for i in range(named + ids)]
            types = dict(entries(0))
            def resource(kind, identity=None):
                node = types[kind]
                if not node & 0x80000000: raise ValueError('expected resource directory')
                choices = dict(entries(node & 0x7fffffff))
                node = choices[identity] if identity is not None else next(iter(choices.values()))
                for _ in range(4):
                    if not node & 0x80000000:
                        rva, size = struct.unpack('<II', read(base + node, 8))
                        return read(offset(rva), size)
                    children = entries(node & 0x7fffffff)
                    node = children[0][1]
                raise ValueError('resource nesting too deep')
            group = resource(14)
            reserved, kind, count = struct.unpack_from('<HHH', group)
            if reserved != 0 or kind != 1 or not 1 <= count <= 128 or len(group) < 6 + count * 14:
                return None
            header = bytearray(struct.pack('<HHH', 0, 1, count))
            payload = bytearray(); start = 6 + count * 16
            for i in range(count):
                entry = group[6 + i * 14:20 + i * 14]
                identity = struct.unpack_from('<H', entry, 12)[0]
                icon = resource(3, identity)
                header.extend(entry[:8] + struct.pack('<II', len(icon), start + len(payload)))
                payload.extend(icon)
                if len(payload) > 8 * 1024 * 1024: raise ValueError('icon too large')
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(header + payload)
        return str(output)
    except (OSError, ValueError, KeyError, IndexError, StopIteration, struct.error):
        return None


# Agent product UIDs are not the artwork filenames used by Battle.net's home UI.
BNET_LOGOS = {
    'w1': 'warcraft', 'w1r': 'warcraft-remastered',
    'w2': 'warcraft-II', 'w2bn': 'warcraft-II', 'w2r': 'warcraft-II-remastered',
    'gryphon': 'warcraft-arclight-rumble',
    'w3': 'warcraft-III', 'osi': 'diablo-II', 'diablo3': 'diablo-III',
    'fen': 'diablo-IV', 'wow': 'world-of-warcraft',
    's1': 'starcraft', 's2': 'starcraft-II', 'hs_beta': 'hearthstone',
    'heroes': 'heroes-of-the-storm', 'prometheus': 'overwatch-2',
}


def svg_logo(data):
    """Accept only bounded, self-contained vector images from launcher resources."""
    if len(data) > 1024 * 1024 or b'<!DOCTYPE' in data.upper() or b'<!ENTITY' in data.upper():
        raise ValueError('invalid SVG')
    root = ET.fromstring(data)
    if root.tag != '{http://www.w3.org/2000/svg}svg':
        raise ValueError('expected SVG')
    allowed = {'svg', 'g', 'path', 'circle', 'ellipse', 'rect', 'line', 'polygon',
               'polyline', 'title', 'desc', 'defs', 'linearGradient', 'radialGradient',
               'stop', 'clipPath', 'mask', 'use'}
    for element in root.iter():
        if element.tag.removeprefix('{http://www.w3.org/2000/svg}') not in allowed:
            raise ValueError('unsupported SVG element')
        for name, value in element.attrib.items():
            name = name.rsplit('}', 1)[-1].lower()
            if name.startswith('on') or (name == 'href' and not value.startswith('#')):
                raise ValueError('external SVG reference')
            urls = re.findall(r'url\(([^)]*)\)', value, re.I)
            if '@import' in value.lower() or any(not url.strip().strip("\"'").startswith('#') for url in urls):
                raise ValueError('external SVG style')
    return data


def battlenet_client_icon(client_root, uid, cache):
    """Prefer the newest installed client resource; cache by archive fingerprint.

    Unknown products and unsupported client archives return None so the scanner
    can use the installed game's icon. Blizzard assets stay on the user's Mac.
    """
    logo = BNET_LOGOS.get(uid.casefold())
    if logo is None:
        return None
    resource = 'resources\\js\\phoenix_home\\icons\\' + logo + '.svg'
    try:
        versions = []
        for directory in client_root.iterdir():
            match = re.fullmatch(r'Battle\.net\.(\d+)', directory.name, re.I)
            if match and directory.is_dir():
                versions.append((int(match[1]), directory))
        archives = [directory / 'Battle.net.mpq' for _, directory in sorted(versions, reverse=True)]
        archives.append(client_root / 'Battle.net.mpq')
    except OSError:
        return None
    for archive in archives:
        try:
            stat = archive.stat()
            key = hashlib.sha256((str(archive) + str(stat.st_mtime_ns) + str(stat.st_size) + resource).encode()).hexdigest()
            output = Path(cache) / (key + '.svg')
            if output.is_file():
                return str(output)
            with archive.open('rb') as stream:
                data = svg_logo(MPQ(stream).resource(resource))
            output.parent.mkdir(parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(dir=output.parent, delete=False) as temporary:
                staged = Path(temporary.name)
                try:
                    temporary.write(data)
                    temporary.close()
                    staged.replace(output)
                finally:
                    staged.unlink(missing_ok=True)
            return str(output)
        except (OSError, ValueError, KeyError, struct.error, ET.ParseError):
            continue
    return None
