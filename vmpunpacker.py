#!/usr/bin/env python3
import os
import sys
import struct
import lzma
import ctypes
from typing import List, Tuple, Optional
from dataclasses import dataclass
import io
import lief
import numpy as np
import argparse
from bisect import bisect_right
from unicorn import *
from unicorn.x86_const import *

# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMPORT_ENTRY_SIZE = 12

# ELF file format constants
ELF_MAGIC = b'\x7fELF'
ELF_CLASS32 = 1
ELF_CLASS64 = 2
PT_LOAD = 1
ELF32_PHDR_FMT = '<IIIIIIII'  # type, offset, vaddr, paddr, filesz, memsz, flags, align
ELF64_PHDR_FMT = '<IIQQQQQQ'  # type, flags, offset, vaddr, paddr, filesz, memsz, align
ELF32_PHDR_SIZE = 32
ELF64_PHDR_SIZE = 56
ELF32_PHOFF_OFF, ELF32_PHENTSIZE_OFF, ELF32_PHNUM_OFF = 0x1C, 0x2A, 0x2C
ELF64_PHOFF_OFF, ELF64_PHENTSIZE_OFF, ELF64_PHNUM_OFF = 0x20, 0x36, 0x38

# exe sys ?
KNOWN_PLAINTEXT = b'.dll\x00'
LZMA_PROPS_DATA = bytes.fromhex('5d 00 00 00 01')

_U32 = struct.Struct('<I')


def get_memory_mapped_image(pe: lief.PE.Binary, raw_data: bytes) -> bytearray:
    image = bytearray(pe.optional_header.sizeof_image)
    n = min(pe.optional_header.sizeof_headers, len(raw_data))
    image[:n] = raw_data[:n]
    for section in pe.sections:
        raw_size = section.sizeof_raw_data
        if raw_size == 0:
            continue
        va = section.virtual_address
        src_off = section.pointerto_raw_data
        chunk = raw_data[src_off:src_off + raw_size]
        image[va:va + len(chunk)] = chunk
    return image


def rol32(v, s): return ((v << (s & 0x1f)) | (v >> (-s & 0x1f))) & 0xFFFFFFFF
def ror32(v, s): return ((v >> (s & 0x1f)) | (v << (-s & 0x1f))) & 0xFFFFFFFF


class MappedRanges:
    """Fast O(log n) membership test for mapped RVAs (section ranges)."""

    __slots__ = ('starts', 'ends', 'np_starts', 'np_ends')

    def __init__(self, pe: lief.PE.Binary):
        starts = []
        ends = []
        for s in pe.sections:
            starts.append(s.virtual_address)
            ends.append(s.virtual_address + max(s.virtual_size, s.sizeof_raw_data))
        self.starts = starts
        self.ends = ends
        self.np_starts = np.asarray(starts, dtype=np.uint32)
        self.np_ends = np.asarray(ends, dtype=np.uint32)

    def __contains__(self, rva):
        i = bisect_right(self.starts, rva) - 1
        return i >= 0 and rva < self.ends[i]


def find_descriptor_candidates(mm, mapped, sec_start, sec_end):
    """Yield candidate offsets ``ea`` whose first three u32 words look like an
    import descriptor (two in-section RVAs + one mapped RVA).

    Vectorised with numpy: all four byte residues are scanned as unaligned u32
    arrays, so every offset from ``sec_start`` to ``sec_end - 12`` is checked,
    identical to a plain byte-by-byte loop.
    """
    hi = sec_end - 12
    if hi < sec_start:
        return
    starts = mapped.np_starts
    ends = mapped.np_ends
    for r in range(4):
        base = sec_start + ((r - sec_start) & 3)
        if base > hi:
            continue
        n = (hi - base) // 4 + 1
        arr = np.ndarray(shape=(n,), dtype='<u4', buffer=mm, offset=base, strides=(4,))
        a, b, c = arr[:-2], arr[1:-1], arr[2:]
        ok = (a >= sec_start) & (a < sec_end) & (b >= sec_start) & (b < sec_end)
        idx = np.nonzero(ok)[0]
        if len(idx):
            cs = c[idx]
            j = np.searchsorted(starts, cs, side='right') - 1
            good = (j >= 0) & (cs < ends[np.clip(j, 0, None)])
            for i in idx[good]:
                yield base + 4 * int(i)


def decrypt_string(mm, rva, key, max_len=0x100):
    """Decode a VMProtect-encrypted null-terminated string at ``rva``."""
    out = bytearray()
    size = len(mm)
    for i in range(max_len):
        pos = rva + i
        if pos >= size:
            break
        ch = ((rol32(key, i) + i) ^ mm[pos]) & 0xFF
        if ch == 0:
            break
        out.append(ch)
    return bytes(out)


def _iter_import_descriptors_raw(mm, mapped, dll_info, max_dlls=100):
    """Yield ``(dll_name_rva, [(name, slot_rva, key), ...])`` per valid
    DLL import-descriptor starting at ``dll_info``.

    Stops at the first invalid entry (mirrors the original early-exit
    behavior). Entries are raw RVAs; callers that need plaintext must
    decrypt them with the packing key.
    """
    u32 = _U32.unpack_from
    size = len(mm)
    for _ in range(max_dlls):
        if dll_info + 4 > size:
            return
        dll_name_rva = u32(mm, dll_info)[0]
        if dll_name_rva not in mapped:
            return
        apis = []
        import_info = dll_info + 4
        while True:
            if import_info + 12 > size:
                return
            name = u32(mm, import_info)[0]
            if name == 0:
                import_info += 4
                break
            if not (name & IMAGE_ORDINAL_FLAG32) and name not in mapped:
                return
            slot_rva = u32(mm, import_info + 4)[0]
            key = u32(mm, import_info + 8)[0]
            apis.append((name, slot_rva, key))
            import_info += IMPORT_ENTRY_SIZE
        dll_info = import_info
        yield dll_name_rva, apis


def count_valid_dll_descriptors(mm, mapped, dll_info, max_dlls=100):
    """Count consecutive DLL import-descriptor entries starting at ``dll_info``."""
    return sum(1 for _ in _iter_import_descriptors_raw(mm, mapped, dll_info, max_dlls))


def parse_import_descriptors(mm, mapped, key, dll_info, max_dlls=100):
    """Parse the full DLL import-descriptor chain starting at ``dll_info``.

    Returns a list of ``(dll_name, [(api, slot_rva, key), ...])`` tuples,
    truncated at the first invalid entry.
    """
    result = []
    for dll_name_rva, apis in _iter_import_descriptors_raw(mm, mapped, dll_info, max_dlls):
        dll_name = decrypt_string(mm, dll_name_rva, key).decode('latin-1')
        parsed = []
        for name, slot_rva, key_ in apis:
            if name & IMAGE_ORDINAL_FLAG32:
                api = f'ordinal_{name & 0xFFFF}'
            else:
                api = decrypt_string(mm, name, key).decode('latin-1')
            parsed.append((api, slot_rva, key_))
        result.append((dll_name, parsed))
    return result


@dataclass
class PACKER_INFO:
    """Python implementation corresponding to C++ struct"""
    Src: int  # uint32
    Dst: int  # uint32


@dataclass
class Region:
    """A contiguous memory region (section or segment) of a binary.

    ``start``/``end`` use the format's native addressing (RVA for PE,
    virtual address for ELF); ``raw_size`` is the on-disk size when relevant.
    """
    start: int
    end: int
    raw_size: int = 0

def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"


def find_vmp_section(pe: lief.PE.Binary):
    for section in reversed(pe.sections):
        if section.sizeof_raw_data and section.pointerto_raw_data and \
            section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE) and \
            section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ) and \
            not section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE):
            return section
    return None


def scan_packer_info_candidates(image, scan_lo, scan_hi, val_lo, val_hi, n):
    """Yield candidate ``info_base`` offsets of a PACKER_INFO array.

    A candidate is an image offset where the ``Src`` words -- read as u32 at
    ``info_base``, ``info_base + 8``, ... ``info_base + 8 * (n - 1)`` -- all
    fall within ``[val_lo, val_hi)``. Every byte offset in ``[scan_lo,
    scan_hi)`` is checked (vectorised with numpy over the four byte residues).

    ``scan_lo``/``scan_hi``/``info_base`` are image offsets while
    ``val_lo``/``val_hi`` are compared against the raw u32 values, so the
    caller controls the address space of each.
    """
    candidates = []
    for align in range(4):
        base = scan_lo + ((align - scan_lo) & 3)
        if base >= scan_hi:
            continue
        total = (len(image) - base) // 4
        if total <= 2 * (n - 1):
            continue
        need = min(total - 2 * (n - 1), (scan_hi - 1 - base) // 4 + 1)
        if need <= 0:
            continue
        arr = np.ndarray(shape=(need + 2 * (n - 1),), dtype='<u4',
                         buffer=image, offset=base, strides=(4,))
        ok = (arr[:need] >= val_lo) & (arr[:need] < val_hi)
        for i in range(1, n):
            ok &= (arr[2 * i:2 * i + need] >= val_lo) & \
                  (arr[2 * i:2 * i + need] < val_hi)
        for j in np.nonzero(ok)[0]:
            candidates.append(base + 4 * int(j))
    candidates.sort()
    return candidates


def decode_packer_info(image, info_base, n, key_seed, validate):
    """Decode a PACKER_INFO array at ``info_base``.

    Derives the start key from the stored ``Dst`` word and the format key seed
    (``xor seed -> ror32 7``), then walks ``n`` entries applying ``rol32 7``
    and ``dst ^= key``. ``validate(image, src, dst, i)`` applies the
    format-specific sanity check; returns ``None`` if any entry is invalid.
    """
    key = _U32.unpack_from(image, info_base + 4)[0]
    key ^= key_seed
    key = ror32(key, 7)
    key_base = key
    entries = []
    for i in range(n):
        key = rol32(key, 7)
        src = _U32.unpack_from(image, info_base + i * 8)[0]
        dst = _U32.unpack_from(image, info_base + i * 8 + 4)[0]
        dst ^= key
        if not validate(image, src, dst, i):
            return None
        entries.append(PACKER_INFO(src, dst))
    return key_base, entries


def decompress_blocks(image, source, entries, backend, props=None):
    """LZMA-decompress every PACKER_INFO block into ``image``.

    ``source`` is a pristine copy of the memory image (compressed blocks are
    read from it so writes to ``image`` cannot corrupt later blocks);
    ``backend`` supplies ``read_compressed(Src)`` and ``target_offset(Dst)``.
    """
    if not entries or len(entries) <= 1:
        return
    props = LZMA_PROPS_DATA if props is None else props
    try:
        for block_idx, info in enumerate(entries):
            compressed_data = backend.read_compressed(info.Src, source)
            target = backend.target_offset(info.Dst)
            if target >= len(image):
                raise RuntimeError(
                    f"Block {block_idx}: PACKER_INFO.Dst (decompression target "
                    f"{to_hex_string(info.Dst)}) exceeds image boundary "
                    f"({to_hex_string(len(image))}).")

            decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_ALONE)
            try:
                decompressed_data = decompressor.decompress(
                    props + b'\xFF' * 8 + compressed_data)
            except lzma.LZMAError as e:
                raise RuntimeError(f"LZMA decompression error: {str(e)}")

            available_space = len(image) - target
            if len(decompressed_data) <= available_space:
                image[target:target + len(decompressed_data)] = decompressed_data
            else:
                print(f"Warning: Block {block_idx}: Decompressed data size "
                      f"exceeds available space in image")
                image[target:target + available_space] = \
                    decompressed_data[:available_space]
            print(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")
    except Exception as e:
        raise RuntimeError(f"Error processing LZMA data: {str(e)}")


class FormatBackend:
    """Format-specific hooks for the shared unpack pipeline."""

    kind = '?'

    def __init__(self, data: bytes):
        self.data = data
        self.binary = self.parse(data)
        self.image_base = 0

    def parse(self, data):
        raise NotImplementedError

    def build_image(self):
        """Return the (mutable) memory-mapped image; set ``image_base``."""
        raise NotImplementedError

    def find_vmp_region(self):
        """Return the ``Region`` holding the VMP stub, or ``None``."""
        raise NotImplementedError

    def reserved_regions(self):
        """Return the regions VMProtect reserved for unpacked data."""
        raise NotImplementedError

    def region_count(self, reserved):
        return len(reserved)

    def key_seed(self, reserved):
        raise NotImplementedError

    def scan_bounds(self, region):
        """Return ``(scan_lo, scan_hi, val_lo, val_hi)`` for the scan."""
        raise NotImplementedError

    def validate_entry(self, image, src, dst, i):
        raise NotImplementedError

    def read_compressed(self, src, source):
        raise NotImplementedError

    def target_offset(self, dst):
        raise NotImplementedError

    def normalize_headers(self, image):
        raise NotImplementedError


def get_memory_mapped_elf_image(elf: lief.ELF.Binary):
    """Build a memory image from PT_LOAD segments; returns (image, min_vaddr)."""
    load_segments = [seg for seg in elf.segments
                     if seg.type == lief.ELF.Segment.TYPE.LOAD]
    if not load_segments:
        load_segments = [seg for seg in elf.segments if seg.type.value == PT_LOAD]
    if not load_segments:
        raise ValueError("No PT_LOAD segments found")

    min_vaddr = min(seg.virtual_address for seg in load_segments)
    max_vaddr_end = max(seg.virtual_address + seg.virtual_size
                        for seg in load_segments)
    image = bytearray(max_vaddr_end - min_vaddr)
    for seg in load_segments:
        offset = seg.virtual_address - min_vaddr
        content = bytes(seg.content)
        image[offset:offset + len(content)] = content
    return image, min_vaddr


class PEFileBackend(FormatBackend):
    kind = 'PE'

    def parse(self, data):
        try:
            return lief.PE.parse(data)
        except Exception as e:
            raise RuntimeError(f"Invalid PE file format: {str(e)}")

    def build_image(self):
        return get_memory_mapped_image(self.binary, self.data)

    def find_vmp_region(self):
        section = find_vmp_section(self.binary)
        if section is None:
            return None
        return Region(section.virtual_address,
                      section.virtual_address + max(section.virtual_size,
                                                    section.sizeof_raw_data),
                      section.sizeof_raw_data)

    def reserved_regions(self):
        regions = []
        for s in self.binary.sections:
            if s.sizeof_raw_data == 0 and s.pointerto_raw_data == 0 and \
                    not s.has_characteristic(
                        lief.PE.Section.CHARACTERISTICS.CNT_UNINITIALIZED_DATA):
                regions.append(Region(
                    s.virtual_address,
                    s.virtual_address + max(s.virtual_size, s.sizeof_raw_data)))
        return regions

    def key_seed(self, reserved):
        return reserved[0].start

    def scan_bounds(self, region):
        return (region.start, region.start + region.raw_size - 12,
                region.start, region.end)

    def validate_entry(self, image, src, dst, i):
        return (dst & 0xFFF) == 0

    def read_compressed(self, src, source):
        offset = self.binary.rva_to_offset(src)
        if offset is None:
            raise ValueError(f'RVA {to_hex_string(src)} not in any section')
        return self.data[offset:]

    def target_offset(self, dst):
        return dst

    def normalize_headers(self, image):
        pe = self.binary
        size_of_image = len(image)
        for i, section in enumerate(pe.sections):
            virtual_address = section.virtual_address
            virtual_size = section.virtual_size
            size_of_raw_data = section.sizeof_raw_data
            pointer_to_raw_data = section.pointerto_raw_data
            section_name = section.name.rstrip('\0')

            if pointer_to_raw_data != 0 and size_of_raw_data > 0:
                if pointer_to_raw_data + size_of_raw_data <= len(self.data) and \
                        virtual_address + size_of_raw_data <= size_of_image:
                    image[virtual_address:virtual_address + size_of_raw_data] = \
                        self.data[pointer_to_raw_data:
                                  pointer_to_raw_data + size_of_raw_data]
                else:
                    print(f"Warning: Section {section_name} data exceeds boundaries. "
                          f"RawOffset={to_hex_string(pointer_to_raw_data)}, "
                          f"RawSize={to_hex_string(size_of_raw_data)}, "
                          f"VA={to_hex_string(virtual_address)}. Skipping copy.")

            nt_off = pe.dos_header.addressof_new_exeheader
            section_offset = nt_off + 24 + pe.header.sizeof_optional_header + i * 40
            struct.pack_into("<I", image, section_offset + 20, virtual_address)
            if virtual_size > 0:
                struct.pack_into("<I", image, section_offset + 16, virtual_size)


class ELFBackend(FormatBackend):
    kind = 'ELF'

    def parse(self, data):
        try:
            return lief.ELF.parse(data)
        except Exception as e:
            raise RuntimeError(f"Invalid ELF file format: {str(e)}")

    def build_image(self):
        image, min_vaddr = get_memory_mapped_elf_image(self.binary)
        self.image_base = min_vaddr
        return image

    def _load_segments(self):
        return [seg for seg in self.binary.segments
                if seg.type == lief.ELF.Segment.TYPE.LOAD]

    def find_vmp_region(self):
        for segment in self._load_segments():
            if (segment.physical_size == segment.virtual_size and
                    segment.file_offset < 0x1000 and
                    (segment.flags & (lief.ELF.Segment.FLAGS.R |
                                      lief.ELF.Segment.FLAGS.X))):
                return Region(segment.virtual_address,
                              segment.virtual_address + segment.virtual_size)
        return None

    def reserved_regions(self):
        regions = []
        for segment in self._load_segments():
            if (segment.physical_address != 0 and
                    segment.physical_size == 0 and
                    segment.virtual_size > 0x1000):
                regions.append(Region(
                    segment.virtual_address,
                    segment.virtual_address + segment.virtual_size))
        return regions

    def region_count(self, reserved):
        return len(reserved) + 1

    def key_seed(self, reserved):
        first_load = self._load_segments()[0]
        return first_load.virtual_address + first_load.physical_size

    def scan_bounds(self, region):
        scan_lo = region.start - self.image_base
        return (scan_lo, scan_lo + (region.end - region.start),
                region.start, region.end)

    def validate_entry(self, image, src, dst, i):
        offset = src - self.image_base
        if not (0 <= offset < len(image)):
            return False
        return image[offset] == 0

    def read_compressed(self, src, source):
        return source[src - self.image_base:]

    def target_offset(self, dst):
        return dst - self.image_base

    def normalize_headers(self, image):
        is64 = self.data[4] == ELF_CLASS64
        if is64:
            phoff = struct.unpack_from('<Q', image, ELF64_PHOFF_OFF)[0]
            phentsize = struct.unpack_from('<H', image, ELF64_PHENTSIZE_OFF)[0]
            phnum = struct.unpack_from('<H', image, ELF64_PHNUM_OFF)[0]
            fmt = ELF64_PHDR_FMT
        else:
            phoff = struct.unpack_from('<I', image, ELF32_PHOFF_OFF)[0]
            phentsize = struct.unpack_from('<H', image, ELF32_PHENTSIZE_OFF)[0]
            phnum = struct.unpack_from('<H', image, ELF32_PHNUM_OFF)[0]
            fmt = ELF32_PHDR_FMT

        load_type = lief.ELF.Segment.TYPE.LOAD.value
        for i in range(phnum):
            base = phoff + i * phentsize
            if is64:
                type_, flags, offset, vaddr, paddr, filesz, memsz, align = \
                    struct.unpack_from(fmt, image, base)
                if type_ == load_type:
                    offset = vaddr - self.image_base
                    filesz = memsz
                struct.pack_into(fmt, image, base, type_, flags, offset, vaddr,
                                 paddr, filesz, memsz, align)
            else:
                type_, offset, vaddr, paddr, filesz, memsz, flags, align = \
                    struct.unpack_from(fmt, image, base)
                if type_ == load_type:
                    offset = vaddr - self.image_base
                    filesz = memsz
                struct.pack_into(fmt, image, base, type_, offset, vaddr, paddr,
                                 filesz, memsz, flags, align)


def unpack_image(backend: FormatBackend) -> bytes:
    """Run the shared PE/ELF unpack pipeline for ``backend``."""
    image = backend.build_image()
    if not image:
        return b''

    region = backend.find_vmp_region()
    if region is None:
        return b''

    reserved = backend.reserved_regions()
    if not reserved:
        return b''

    n = backend.region_count(reserved)
    key_seed = backend.key_seed(reserved)
    scan_lo, scan_hi, val_lo, val_hi = backend.scan_bounds(region)
    source = bytes(image)

    entries = None
    for info_base in scan_packer_info_candidates(
            image, scan_lo, scan_hi, val_lo, val_hi, n):
        result = decode_packer_info(image, info_base, n, key_seed,
                                    backend.validate_entry)
        if result is not None:
            key_base, entries = result
            print('key:', hex(key_base))
            break
    if entries is None:
        return b''

    backend.normalize_headers(image)
    decompress_blocks(image, source, entries, backend)
    return bytes(image)


def unpack_pe(packed_pe_data: bytes) -> bytes:
    """
    Unpack a VMProtect protected PE file

    Args:
        packed_pe_data: Byte content of the packed PE file

    Returns:
        Unpacked PE file byte content
    """
    if not packed_pe_data:
        raise RuntimeError("Packed PE data is null or empty.")
    return unpack_image(PEFileBackend(packed_pe_data))


def unpack_elf(packed_elf_data: bytes) -> bytes:
    """
    Unpack a VMProtect protected ELF file

    Args:
        packed_elf_data: Byte content of the packed ELF file

    Returns:
        Unpacked ELF file byte content (memory image)
    """
    if not packed_elf_data:
        raise RuntimeError("Packed ELF data is null or empty.")
    return unpack_image(ELFBackend(packed_elf_data))


def detect_backend(data: bytes) -> FormatBackend:
    """Pick a backend from the file magic (PE 'MZ' or ELF)."""
    if data[:2] == b'MZ':
        return PEFileBackend(data)
    if data[:4] == ELF_MAGIC:
        return ELFBackend(data)
    raise RuntimeError("Unsupported file format: expected PE (MZ) or ELF")


def derive_key_hints_at_offset(image, known_plaintext, rva, offset=0):
    if not known_plaintext:
        return
    key_leak = 0
    key_mask = 0
    prev_byte = None
    for i, expected in enumerate(known_plaintext):
        n = offset + i
        if rva + n >= len(image):
            return
        byte = image[rva + n] ^ expected
        byte = (byte - n) & 0xFF
        if prev_byte is not None and (prev_byte & 0x7F) != (byte >> 1):
            return
        key_leak |= ror32(byte, n)
        key_mask |= ror32(0xFF, n)
        prev_byte = byte
    return offset, key_leak, key_mask


def derive_key_hints(image, known_plaintext, rva):
    for offset in range(0x100):
        result = derive_key_hints_at_offset(image, known_plaintext, rva, offset)
        if result is not None:
            return result


def find_key(pe: lief.PE.Binary, raw_data: bytes):
    image = get_memory_mapped_image(pe, raw_data)
    mapped = MappedRanges(pe)
    vmp_section = find_vmp_section(pe)

    sec_start = vmp_section.virtual_address
    sec_size = max(vmp_section.virtual_size, vmp_section.sizeof_raw_data)
    sec_end = min(sec_start + sec_size, len(image))

    code = image[sec_start:sec_end]

    best_rva = None
    best_count = 0
    for rva in find_descriptor_candidates(image, mapped, sec_start, sec_end):
        count = count_valid_dll_descriptors(image, mapped, rva)
        if count > best_count:
            best_rva = rva
            best_count = count

    if best_rva is None:
        print('no descriptor candidates found')
        return 0

    first_dll_name_rva = _U32.unpack_from(image, best_rva)[0]
    first_api_name_rva = _U32.unpack_from(image, best_rva + 4)[0]

    if result := derive_key_hints(image, KNOWN_PLAINTEXT, first_dll_name_rva):
        offset, key_leak, key_mask = result
        print('found offset', offset, hex(key_leak), hex(key_mask))
        pos = code.find(b'\xB8')
        while pos != -1 and pos + 5 <= len(code):
            ea = sec_start + pos
            # mov eax, key
            key = _U32.unpack_from(code, pos + 1)[0]
            if (key & key_mask) == key_leak:
                try:
                    dll_name = decrypt_string(image, first_dll_name_rva, key).decode()
                    api_name = decrypt_string(image, first_api_name_rva, key).decode()
                    if dll_name and dll_name.isprintable() and api_name and api_name.isprintable():
                        return key
                except Exception:
                    pass
            pos = code.find(b'\xB8', pos + 1)

    # 3.10.6
    for dll_name_rva, apis in _iter_import_descriptors_raw(image, mapped, best_rva):
        result = derive_key_hints_at_offset(image, b'api-ms-win-crt-heap-l1-1-0.dll', dll_name_rva)
        if result is not None:
            offset, key_leak, key_mask = result
            if key_mask == 0xffffffff:
                return key_leak
        for api_name_rva, _, _ in apis:
            if api_name_rva & IMAGE_ORDINAL_FLAG32:
                continue
            result = derive_key_hints_at_offset(image, b'InitializeCriticalSection', api_name_rva)
            if result is not None:
                offset, key_leak, key_mask = result
                if key_mask == 0xffffffff:
                    return key_leak
    return 0


def parse_va_list(s):
    """Parse a comma-separated list of hex addresses (image-base VAs)."""
    return [int(x, 0) for x in s.split(',') if x.strip()]


def find_import_descriptors(pe: lief.PE.Binary, key, raw_data: bytes):
    """Locate the VMP import-descriptor block.

    Returns ``(dll_info_rva, [(dll_name, [(api, slot_rva, key), ...]), ...])``
    or ``(None, [])`` when nothing valid is found.
    """
    vmp_section = find_vmp_section(pe)
    if vmp_section is None:
        return None, []
    mm = get_memory_mapped_image(pe, raw_data)
    mapped = MappedRanges(pe)
    sec_start = vmp_section.virtual_address
    sec_end = min(sec_start + max(vmp_section.virtual_size,
                                  vmp_section.sizeof_raw_data), len(mm))
    best_ea, best_count = None, 0
    for ea in find_descriptor_candidates(mm, mapped, sec_start, sec_end):
        count = count_valid_dll_descriptors(mm, mapped, ea)
        if count > best_count:
            best_ea, best_count = ea, count
    if best_ea is None:
        return None, []
    return best_ea, parse_import_descriptors(mm, mapped, key, best_ea)


def build_import_map(dlls):
    """Map IAT slot RVA -> 'DLL!api' using dump_imports' descriptor parser."""
    result = {}
    for dll_name, apis in dlls:
        for api, address, _ in apis:
            if address is not None:
                result[address] = f'{dll_name}!{api}'
    return result


def build_fix_section(pe: lief.PE.Binary, dlls, sites):
    """Build the new section blob: import directory + fresh IAT + redirect stubs.

    The import table is emitted in the standard layout -- one descriptor per
    DLL, with contiguous per-DLL ``OriginalFirstThunk``/``FirstThunk`` arrays
    (the loader fills the IAT slots).  Ordinal imports use a real ordinal
    thunk instead of a bogus hint/name string.

    Returns ``(blob, slot_va, stub_va, descriptors_rva, descriptors_size,
    iat_rva, iat_size)``.
    """
    sec_va = pe.optional_header.sizeof_image
    blob = bytearray()

    def alloc(data, align=8):
        off = len(blob)
        blob.extend(data)
        blob.extend(b'\0' * ((-len(blob)) % align))
        return sec_va + off

    is_x64 = pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
    if is_x64:
        align_size = 8
    else:
        align_size = 4
    # Group imports by DLL, preserving first-seen order (a DLL can appear in
    # several VMP descriptor blocks).
    dll_order = []
    dll_imports = {}
    seen = set()
    for dll_name, apis in dlls:
        for api, slot, _ in apis:
            if (dll_name, api) in seen:
                continue
            seen.add((dll_name, api))
            if dll_name not in dll_imports:
                dll_order.append(dll_name)
                dll_imports[dll_name] = []
            dll_imports[dll_name].append((api, slot))

    # Fresh IAT: one contiguous 8-byte slot per import, grouped by DLL so each
    # descriptor's FirstThunk is a single run.  Allocated first, so the whole
    # IAT is one contiguous region at the section start.
    slot_va = {}
    iat_rva = {}
    iat_size = 0
    for dll_name in dll_order:
        entries = dll_imports[dll_name]
        base = alloc(b'\0' * (8 * len(entries)), align_size)
        iat_rva[dll_name] = base
        iat_size += align_size * len(entries)
        for idx, (api, slot) in enumerate(entries):
            slot_va[slot] = base + idx * align_size
    iat_start = iat_rva[dll_order[0]] if dll_order else None

    # Redirect stubs for call sites without room for a 6-byte call/jmp.
    stub_va = {}
    for rva, kind, api, slot, size in sites:
        stub = struct.pack('<BB', 0xFF, 0x25)
        if is_x64:
            stub += struct.pack('<i', slot_va[slot] - (sec_va + len(blob) + 6))
        else:
            stub += struct.pack('<i', slot_va[slot] + pe.optional_header.imagebase)
        stub_va[(api, slot)] = alloc(stub)

    name_rva = {}
    for dll_name in dll_order:
        name_rva[dll_name] = alloc(dll_name.encode('latin-1') + b'\0', align=2)

    # OriginalFirstThunk arrays: name thunks + trailing NULL terminator.
    oft_rva = {}
    for dll_name in dll_order:
        arr = bytearray()
        for api, slot in dll_imports[dll_name]:
            if api.startswith('ordinal_'):
                if is_x64:
                    arr.extend(struct.pack('<Q', IMAGE_ORDINAL_FLAG64
                                        | int(api.rsplit('_', 1)[1])))
                else:
                    arr.extend(struct.pack('<I', IMAGE_ORDINAL_FLAG32
                                        | int(api.rsplit('_', 1)[1])))
            else:
                hn_rva = alloc(struct.pack('<H', 0) + api.encode('latin-1')
                               + b'\0', align=align_size)
                if is_x64:
                    arr.extend(struct.pack('<Q', hn_rva))
                else:
                    arr.extend(struct.pack('<I', hn_rva))
        arr.extend(b'\0' * align_size)
        oft_rva[dll_name] = alloc(bytes(arr), align=align_size)

    desc_off = len(blob)
    for dll_name in dll_order:
        blob.extend(struct.pack('<5I', oft_rva[dll_name], 0, 0,
                                name_rva[dll_name], iat_rva[dll_name]))
    blob.extend(b'\0' * 20)
    n = sum(len(v) for v in dll_imports.values())
    return (bytes(blob), slot_va, stub_va, sec_va + desc_off,
            20 * (len(dll_order) + 1), iat_start, iat_size)


def add_section(pe: lief.PE.Binary, blob, name='idata', chars=0xC0000040):
    """Append a new section using lief's PE API and return the section.

    The section is placed at ``SizeOfImage`` -- the same RVA base
    ``build_fix_section`` uses for the import table -- and lief aligns
    ``SizeOfRawData`` to the file alignment, lays the raw data out at the end
    of the file and updates ``NumberOfSections``/``SizeOfImage`` when the
    binary is serialized.
    """
    section = lief.PE.Section(name)
    section.content = list(blob)
    section.characteristics = chars
    section.virtual_address = pe.optional_header.sizeof_image
    pe.add_section(section)
    return section


def fix_imports(data, pe: lief.PE.Binary, key, code_rva, internal_stub_rvas=(),
                verbose=False):
    """Rebuild the import table, patch the call sites and write a fixed PE.
    """
    dll_info, dlls = find_import_descriptors(pe, key, data)
    if dll_info is None:
        raise SystemExit('no import descriptors found')
    print(f'import descriptors at {dll_info:#x}, {len(dlls)} DLLs')
    if verbose:
        for dll_name, apis in dlls:
            for api, slot, key_ in apis:
                print(f'{dll_name} {api} {slot:#x} {key_:#x}')

    import_map = build_import_map(dlls)
    code_section, code_rva = find_code_section(pe, code_rva)
    sites = classify_sites(pe, data, import_map, code_section, code_rva,
                           internal_stub_rvas, verbose)
    if not sites:
        raise SystemExit('no import call sites classified')
    print(f'{len(sites)} import call sites classified')

    blob, slot_va, stub_va, desc_rva, desc_size, iat_rva, iat_size = \
        build_fix_section(pe, dlls, sites)
    base = pe.optional_header.imagebase

    out = bytearray(data)
    for rva, kind, api, slot, size in sites:
        at = rva
        if size >= 6:
            opcode = b'\xFF\x15' if kind == 'CALL' else b'\xFF\x25'
            if pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64:
                patch = opcode + struct.pack(
                    '<i', base + slot_va[slot] - (base + at + 6))
            else:
                patch = opcode + struct.pack('<I', base + slot_va[slot])
            out[pe.rva_to_offset(at):pe.rva_to_offset(at) + 6] = patch
        else:
            opcode = b'\xE8' if kind == 'CALL' else b'\xE9'
            patch = opcode + struct.pack(
                '<i', base + stub_va[(api, slot)] - (base + at + 5))
            out[pe.rva_to_offset(at):pe.rva_to_offset(at) + 5] = patch

    pe = lief.PE.parse(bytes(out))
    pe.remove_all_imports()
    add_section(pe, blob, 'idata', chars=0xE0000040)
    desc = pe.data_directory(lief.PE.DataDirectory.TYPES.IMPORT_TABLE)
    desc.rva, desc.size = desc_rva, desc_size
    iat = pe.data_directory(lief.PE.DataDirectory.TYPES.IAT)
    iat.rva, iat.size = iat_rva, iat_size

    print(f'import dir rva={desc_rva:#x} '
          f'size={desc_size:#x} ({sum(len(a) for _, a in dlls)} imports)')
    return bytes(pe.write_to_bytes())


def find_code_section(pe: lief.PE.Binary, code_rva=None):
    """Return (section, rva) of the code to scan.

    Defaults to the first executable code section; override with ``code_rva``.
    """
    if code_rva is not None:
        section = pe.section_from_rva(code_rva)
        if section is not None:
            return section, code_rva
        raise SystemExit(f'no section contains rva {code_rva:#x}')
    for section in pe.sections:
        if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE) and section.has_characteristic(lief.PE.Section.CHARACTERISTICS.CNT_CODE):
            return section, section.virtual_address
    raise SystemExit('no executable code section found')


# def hook_code(uc, address, size, userdata):
#     print(hex(address))
#     pass


def hook_mem_read(uc, access, address, size, value, userdata):
    # Only fires for reads in the mapped image range; the stack lives at
    # 0x100000, outside that range, so stack reads never reach this hook.
    userdata.read_record_list.append(address)


class Emu:
    def __init__(self, pe: lief.PE.Binary, raw_data, import_map=None, verbose=False):
        self.import_map = import_map or {}
        self.verbose = verbose
        base = pe.optional_header.imagebase
        self.is_x64 = pe.header.machine == lief.PE.Header.MACHINE_TYPES.AMD64
        if self.is_x64:
            uc = Uc(UC_ARCH_X86, UC_MODE_64)
        else:
            uc = Uc(UC_ARCH_X86, UC_MODE_32)
        for section in pe.sections:
            if not section.sizeof_raw_data:
                continue
            podata = raw_data[section.pointerto_raw_data:
                              section.pointerto_raw_data + section.sizeof_raw_data]
            size = (section.sizeof_raw_data + 0xFFF) & ~0xFFF

            prot = UC_PROT_NONE
            if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_READ):
                prot |= UC_PROT_READ
            if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_WRITE):
                prot |= UC_PROT_WRITE
            if section.has_characteristic(lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE):
                prot |= UC_PROT_EXEC

            uc.mem_map(base + section.virtual_address, size, prot)
            uc.mem_write(base + section.virtual_address, podata)

        self.read_record_list = []
        self.stack_address = 0x100000
        self.stack_size = 0x20000
        self.stack_init = self.stack_address + self.stack_size - 0x1000
        self.stack_reg = UC_X86_REG_RSP if self.is_x64 else UC_X86_REG_ESP
        uc.mem_map(self.stack_address, self.stack_size)
        uc.reg_write(self.stack_reg, self.stack_init)
        # uc.hook_add(UC_HOOK_CODE, hook_code, self)
        uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read, self,
                    base, base + pe.optional_header.sizeof_image)
        self.uc_context = uc.context_save()
        
        self.pe = pe
        self.uc = uc

    def reset(self):
        """Reset per-run state so one instance can be reused across sites."""
        self.read_record_list.clear()
        self.uc.context_restore(self.uc_context)
        self.uc.mem_write(self.stack_address, b'\0' * self.stack_size)

    def resolve_import(self, address):
        info = self.import_map.get(address - self.pe.optional_header.imagebase)
        return info if info else '?'

    def run(self, address):
        """Emulate the call site; return (kind, target) or None if unclassified."""
        self.reset()
        self.last = {'reads': []}
        try:
            self.uc.emu_start(address, -1, 0, 1000)
            self.last['stop'] = 'instruction-count limit reached'
        except Exception as e:
            self.last['stop'] = str(e) if isinstance(e, UcError) else repr(e)
            try:
                self.last['rip'] = self.uc.reg_read(UC_X86_REG_RIP if self.is_x64 else UC_X86_REG_EIP)
            except Exception:
                pass
        result = self._classify(address)
        if self.verbose:
            print(f'[emu] {address:#x}  {self.last["stop"]}'
                  f'  reads={len(self.read_record_list)}'
                  + (f' {[hex(x) for x in self.read_record_list]}'
                     if self.read_record_list else ''))
            if result:
                address, kind, target, size = result
                print(f'[emu]   -> {kind} {target}  '
                      f'slot={self.last.get("slot", 0):#x}  size={size}')
            else:
                print(f'[emu]   -> unclassified: '
                      f'{self.last.get("reason", "no reason recorded")}')
        return result

    def _classify(self, address):
        """Apply the CALL/JMP heuristics; records a failure reason in ``last``."""
        if len(self.read_record_list) != 1:
            self.last['reason'] = (f'{len(self.read_record_list)} non-stack '
                                   f'memory reads')
            return

        read_addr = self.read_record_list[0]
        target = self.resolve_import(read_addr)
        self.read_addr = read_addr

        rsp = self.uc.reg_read(self.stack_reg)
        delta_rsp = rsp - self.stack_init

        try:
            prev_code = self.uc.mem_read(address - 1, 1)[0]
        except UcError:
            prev_code = None
        is_push_reg = prev_code is not None and 0x50 <= prev_code <= 0x57

        size = 6
        if self.is_x64:
            return_address = struct.unpack('<Q', self.uc.mem_read(rsp, 8))[0]
            address_size = 8
        else:
            return_address = struct.unpack('<I', self.uc.mem_read(rsp, 4))[0]
            address_size = 4
        if return_address:
            delta_rip = return_address - address
            if delta_rip == 6 and delta_rsp == -address_size:
                kind = 'CALL'
            elif delta_rip == 5 and delta_rsp == 0:
                if not is_push_reg:
                    self.last['reason'] = ('return addr +5, rsp balanced, but '
                                        'no preceding push register')
                    return
                kind = 'CALL'
                address -= 1
            elif delta_rip == 5 and delta_rsp == -address_size:
                kind = 'CALL'
                size = 5
            else:
                self.last['reason'] = (f'return address={return_address:#x} '
                                    f'delta_rip={delta_rip:#x} '
                                    f'delta_rsp={delta_rsp:#x}')
                return
        else:
            if delta_rsp == 0:
                kind = 'JMP'
            elif delta_rsp == address_size and is_push_reg:
                kind = 'JMP'
                address -= 1
            else:
                self.last['reason'] = (f'no return address, '
                                    f'delta_rsp={delta_rsp:#x}')
                return
        self.last['slot'] = read_addr - self.pe.optional_header.imagebase
        return address, kind, target, size


def classify_sites(pe: lief.PE.Binary, raw_data, import_map, code_section, code_rva, internal_stub_rvas=(),
                   verbose=False):
    """Classify cross-section E8 call sites and direct IAT indirection stubs.

    Returns a list of ``(rva, kind, api, slot_rva, size)`` where ``kind`` is
    'CALL' or 'JMP', ``api`` the short API name, ``slot_rva`` the original IAT
    slot the stub reads and ``size`` the number of bytes to overwrite.

    Two kinds of sites are picked up:

    * ``push; call`` / ``call`` / ``jmp`` into a VMP stub in another
      executable section, resolved by emulating the stub (exactly one
      non-stack memory read = the IAT slot fetch).  Call sites whose first
      jump lands on one of ``internal_stub_rvas`` (stubs VMProtect placed
      inside the code section) are emulated as well.
    * plain ``call/jmp [rip+disp]`` indirections that already target an import
      slot directly.  VMProtect emits these for unencrypted IAT entries
      (``key == 0``), e.g. ``memcpy``, so they must be repointed to the fresh
      IAT as well.
    """
    base = pe.optional_header.imagebase
    code = raw_data[code_section.pointerto_raw_data:
                    code_section.pointerto_raw_data + code_section.sizeof_raw_data]
    internal = set(internal_stub_rvas)
    emu = Emu(pe, raw_data, import_map, verbose)
    sites = []
    i = code.find(b'\xe8')
    while i != -1:
        rva = code_rva + i
        try:
            dst = rva + struct.unpack('<i', code[i + 1:i + 5])[0] + 5
        except struct.error:
            i = code.find(b'\xe8', i + 1)
            continue
        if dst > 0:
            dst_section = pe.section_from_rva(dst)
        else:
            dst_section = None
        if dst_section is not None:
            is_code = dst_section.virtual_address == code_section.virtual_address
            cross_section = (not is_code and dst_section.has_characteristic(
                lief.PE.Section.CHARACTERISTICS.MEM_EXECUTE))
            internal_stub = is_code and dst in internal
        else:
            cross_section = False
            internal_stub = False
        if not (cross_section or internal_stub):
            i = code.find(b'\xe8', i + 1)
            continue
        if verbose:
            loc = dst_section.name if dst_section else '?'
            print(f'[site] {base + rva:#x}: E8 -> {base + dst:#x} '
                  f'({loc}, {"internal" if internal_stub else "cross"})')
        result = emu.run(base + rva)
        if result:
            address, kind, target, size = result
            if target != '?':
                api = target.rsplit('!', 1)[1]
                sites.append((address-base, kind, api,
                              emu.read_addr - base, size))
        i = code.find(b'\xe8', i + 1)

    i = code.find(b'\xff')
    while i != -1:
        if i + 6 > len(code):
            break
        if code[i + 1] in (0x15, 0x25):
            disp = struct.unpack('<i', code[i + 2:i + 6])[0]
            slot_rva = code_rva + i + 6 + disp
            info = import_map.get(slot_rva)
            if info is not None:
                kind = 'CALL' if code[i + 1] == 0x15 else 'JMP'
                api = info.rsplit('!', 1)[1]
                sites.append((code_rva + i, kind, api, slot_rva, 6))
        i = code.find(b'\xff', i + 1)
    return sites


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('file', help='path to the VMProtect-protected PE/ELF file')
    parser.add_argument('-k', '--key', type=lambda s: int(s, 0), default=0,
                        help='string decryption key (default: 0, PE only)')
    parser.add_argument('--code-rva', type=lambda s: int(s, 0), default=None,
                        help='code section RVA to scan (default: first executable '
                             'code section, PE only)')
    parser.add_argument('--internal-stubs', type=parse_va_list, default=[],
                        metavar='ADDR',
                        help='comma-separated address(es) of import stubs '
                             'VMProtect reused inside the code section; call '
                             'sites whose first jump lands on them are '
                             'emulated too. Each entry may be an image-base VA '
                             'or an RVA; values >= image base are treated as '
                             'VAs, smaller ones as RVAs '
                             '(e.g. --internal-stubs=0x140001AB4,0x1AB4, PE only)')
    parser.add_argument('-v', '--verbose', action='store_true',
                        help='print per-site emulation diagnostics '
                             '(stop reason, memory reads, classification)')

    args = parser.parse_args()
    packed_filepath = args.file
    
    try:
        # Read packed file
        with open(packed_filepath, 'rb') as f:
            packed_data = f.read()
        
        print(f"Packed file loaded: {packed_filepath}, size: {len(packed_data)} bytes")
        
        # Detect the container format and run the matching unpack pipeline
        backend = detect_backend(packed_data)
        print(f"Format: {backend.kind}")

        print("Unpacking...")
        unpacked_data = unpack_image(backend)
        if not unpacked_data:
            print("Unpacking function failed or produced empty output.")
            unpacked_data = packed_data
        else:
            print(f"Unpacking function completed. Unpacked size: {len(unpacked_data)} bytes")
            unpacked_filepath = args.file + '.dump'
            # Write unpacked file
            with open(unpacked_filepath, 'wb') as f:
                f.write(unpacked_data)
            print(f"Unpacked data written to: {unpacked_filepath}")

        # Import rebuilding is currently only implemented for PE files.
        if backend.kind != 'PE':
            return 0

        print("Fixing imports...")
        pe = lief.PE.parse(unpacked_data)
        base = pe.optional_header.imagebase
        key = args.key if args.key else find_key(pe, unpacked_data)
        print('key:', hex(key))
        if not key:
            return 0
        internal_rvas = [va - base if va >= base else va for va in args.internal_stubs]
        output_filepath = args.file + '.fixed'
        output_data = fix_imports(unpacked_data, pe, key, args.code_rva, internal_rvas, args.verbose)
        with open(output_filepath, 'wb') as f:
            f.write(output_data)
        print(f"Fixed: {output_filepath}")
        return 0
    except Exception as e:
        print(f"Exception occurred during unpacking: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())