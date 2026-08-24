#!/usr/bin/env python3
import os
import sys
import struct
import lzma
import ctypes
from typing import List, Tuple, Optional
from dataclasses import dataclass
import io
import pefile  # Added pefile library import
import numpy as np
import argparse
from bisect import bisect_right
from unicorn import *
from unicorn.x86_const import *

# PE file format constants
IMAGE_DOS_SIGNATURE = 0x5A4D  # MZ
IMAGE_NT_SIGNATURE = 0x00004550  # PE\0\0
IMAGE_SIZEOF_SHORT_NAME = 8
IMAGE_SCN_CNT_UNINITIALIZED_DATA = 0x00000080
LZMA_PROPERTIES_SIZE = 5  # Standard LZMA properties size

IMAGE_SCN_MEM_READ = 0x40000000
IMAGE_SCN_MEM_WRITE = 0x80000000
IMAGE_SCN_MEM_EXECUTE = 0x20000000
IMAGE_SCN_CNT_CODE = 0x00000020

IMAGE_ORDINAL_FLAG32 = 0x80000000
IMAGE_ORDINAL_FLAG64 = 0x8000000000000000
IMPORT_ENTRY_SIZE = 12

# exe sys ?
KNOWN_PLAINTEXT = b'.dll\x00'

_U32 = struct.Struct('<I')

def rol32(v, s): return ((v << (s & 0x1f)) | (v >> (-s & 0x1f))) & 0xFFFFFFFF
def ror32(v, s): return ((v >> (s & 0x1f)) | (v << (-s & 0x1f))) & 0xFFFFFFFF


class MappedRanges:
    """Fast O(log n) membership test for mapped RVAs (pefile section ranges)."""

    __slots__ = ('starts', 'ends', 'np_starts', 'np_ends')

    def __init__(self, pe):
        starts = []
        ends = []
        for s in pe.sections:
            starts.append(s.VirtualAddress)
            ends.append(s.VirtualAddress + max(s.Misc_VirtualSize, s.SizeOfRawData))
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


def count_valid_dll_descriptors(mm, mapped, dll_info, max_dlls=100):
    """Count consecutive DLL import-descriptor entries starting at ``dll_info``.

    Returns the number of fully validated DLL entries before the first
    invalid one (mirrors the original script's early-exit behavior).
    """
    u32 = _U32.unpack_from
    size = len(mm)
    count = 0
    for _ in range(max_dlls):
        if dll_info + 4 > size:
            return count
        dll_name_rva = u32(mm, dll_info)[0]
        if dll_name_rva not in mapped:
            return count
        import_info = dll_info + 4
        while True:
            if import_info + 12 > size:
                return count
            name = u32(mm, import_info)[0]
            if name == 0:
                import_info += 4
                break
            if not (name & IMAGE_ORDINAL_FLAG32) and name not in mapped:
                return count
            import_info += IMPORT_ENTRY_SIZE
        dll_info = import_info
        count += 1
    return count


def parse_import_descriptors(mm, mapped, key, dll_info, max_dlls=100):
    """Parse the full DLL import-descriptor chain starting at ``dll_info``.

    Returns a list of ``(dll_name, [(api, address, key), ...])`` tuples,
    truncated at the first invalid entry.
    """
    u32 = _U32.unpack_from
    size = len(mm)
    result = []
    for _ in range(max_dlls):
        if dll_info + 4 > size:
            break
        dll_name_rva = u32(mm, dll_info)[0]
        if dll_name_rva not in mapped:
            break
        dll_name = decrypt_string(mm, dll_name_rva, key).decode('latin-1')
        apis = []
        import_info = dll_info + 4
        while True:
            if import_info + 12 > size:
                return result
            name = u32(mm, import_info)[0]
            if name == 0:
                import_info += 4
                break
            if not (name & IMAGE_ORDINAL_FLAG32) and name not in mapped:
                return result
            address = u32(mm, import_info + 4)[0]
            key_ = u32(mm, import_info + 8)[0]
            if name & IMAGE_ORDINAL_FLAG32:
                api = f'ordinal_{name & 0xFFFF}'
            else:
                api = decrypt_string(mm, name, key).decode('latin-1')
            apis.append((api, address, key_))
            import_info += IMPORT_ENTRY_SIZE
        dll_info = import_info
        result.append((dll_name, apis))
    return result


@dataclass
class PACKER_INFO:
    """Python implementation corresponding to C++ struct"""
    Src: int  # uint32
    Dst: int  # uint32

def to_hex_string(val, prefix=True):
    """Convert value to hexadecimal string for better error message display"""
    return f"0x{val:x}" if prefix else f"{val:x}"


def find_vmp_section(pe, characteristics=0x68000060) -> pefile.SectionStructure:
    for section in pe.sections:
        if section.Characteristics == characteristics:
            return section
    return None


def scan_packer_info(pe):
    '''
    VMProtect 3.10.5
    '''
    packed_sections: list[pefile.SectionStructure] = []
    for s in pe.sections:
        if s.SizeOfRawData == 0 and s.PointerToRawData == 0 and not s.IMAGE_SCN_CNT_UNINITIALIZED_DATA:
            packed_sections.append(s)

    if not packed_sections:
        return
    
    section = find_vmp_section(pe)
    if not section:
        return

    first_section_rva = packed_sections[0].VirtualAddress
    n = len(packed_sections)

    mm = pe.get_memory_mapped_image()
    sec_start = section.VirtualAddress
    sec_end = sec_start + max(section.Misc_VirtualSize, section.SizeOfRawData)
    stop = sec_start + section.SizeOfRawData - 12

    candidates = []
    for align in range(4):
        base = sec_start + ((align - sec_start) & 3)
        if base >= stop:
            continue
        total = (len(mm) - base) // 4
        if total <= 2 * (n - 1):
            continue
        need = min(total - 2 * (n - 1), (stop - 1 - base) // 4 + 1)
        if need <= 0:
            continue
        arr = np.ndarray(shape=(need + 2 * (n - 1),), dtype='<u4', buffer=mm, offset=base, strides=(4,))
        ok = (arr[:need] >= sec_start) & (arr[:need] < sec_end)
        for i in range(1, n):
            ok &= (arr[2 * i:2 * i + need] >= sec_start) & (arr[2 * i:2 * i + need] < sec_end)
        for j in np.nonzero(ok)[0]:
            candidates.append(base + 4 * int(j))

    candidates.sort()
    for info_base in candidates:
        key = _U32.unpack_from(mm, info_base + 4)[0]
        key ^= first_section_rva
        key = ror32(key, 7)
        start_key = key
        packer_info = []
        valid = True
        for i in range(n):
            key = rol32(key, 7)
            src = _U32.unpack_from(mm, info_base + i * 2 * 4)[0]
            dst = _U32.unpack_from(mm, info_base + (i * 2 + 1) * 4)[0]
            dst ^= key
            if dst & 0xFFF:
                valid = False
                break
            packer_info.append(PACKER_INFO(src, dst))
        if valid:
            print('key:', hex(start_key))
            return info_base, packer_info


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
    
    # Use pefile library to parse PE file
    try:
        pe = pefile.PE(data=packed_pe_data)
    except pefile.PEFormatError as e:
        raise RuntimeError(f"Invalid PE file format: {str(e)}")
    
    # Get basic PE information
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    size_of_headers = pe.OPTIONAL_HEADER.SizeOfHeaders
    
    # Create unpacked image
    unpacked_image = bytearray(size_of_image)
    
    # Copy PE headers
    unpacked_image[:size_of_headers] = packed_pe_data[:size_of_headers]
    
    # Find PACKER_INFO array
    packer_info_array = []
  
    res = scan_packer_info(pe)
    if res is None:
        return b''
    packer_info_rva, packer_info_array = res
    lzma_props_data = bytes.fromhex('5d 00 00 00 01')

    # Copy section data and update section headers in unpacked image
    for i, section in enumerate(pe.sections):
        # Original section header
        virtual_address = section.VirtualAddress
        virtual_size = section.Misc_VirtualSize
        size_of_raw_data = section.SizeOfRawData
        pointer_to_raw_data = section.PointerToRawData
        section_name = section.Name.decode('ascii', errors='ignore').strip('\0')
        
        # Copy section data
        if pointer_to_raw_data != 0 and size_of_raw_data > 0:
            if pointer_to_raw_data + size_of_raw_data <= len(packed_pe_data) and virtual_address + size_of_raw_data <= size_of_image:
                section_data = packed_pe_data[pointer_to_raw_data:pointer_to_raw_data+size_of_raw_data]
                unpacked_image[virtual_address:virtual_address+len(section_data)] = section_data
            else:
                print(f"Warning: Section {section_name} data exceeds boundaries. RawOffset={to_hex_string(pointer_to_raw_data)}, "
                      f"RawSize={to_hex_string(size_of_raw_data)}, VA={to_hex_string(virtual_address)}. Skipping copy.")
        
        # Get section table offset in file
        section_offset = pe.OPTIONAL_HEADER.get_file_offset() + pe.FILE_HEADER.SizeOfOptionalHeader + i * 40
        
        # Update section header in unpacked image
        unpacked_section_offset = section_offset
        
        # Update PointerToRawData to VirtualAddress
        struct.pack_into("<I", unpacked_image, unpacked_section_offset+20, virtual_address)
        
        # If VirtualSize is non-zero, use it as SizeOfRawData
        if virtual_size > 0:
            struct.pack_into("<I", unpacked_image, unpacked_section_offset+16, virtual_size)
    
    # Handle LZMA decompression
    if packer_info_array and len(packer_info_array) > 1:
        try:
            # Process each LZMA block
            for block_idx in range(len(packer_info_array)):
                current_block_info = packer_info_array[block_idx]
                
                compressed_data_rva = current_block_info.Src
                uncompressed_target_rva = current_block_info.Dst
                
                # Use pefile to get file offset
                try:
                    compressed_block_raw_offset = pe.get_offset_from_rva(compressed_data_rva)
                except Exception as e:
                    raise RuntimeError(f"Block {block_idx}: Cannot convert RVA to file offset: {str(e)}")
                
                compressed_data = packed_pe_data[compressed_block_raw_offset:]
                
                if uncompressed_target_rva >= size_of_image:
                    raise RuntimeError(f"Block {block_idx}: PACKER_INFO.Dst (decompression target RVA {to_hex_string(uncompressed_target_rva)}) "
                                      f"exceeds image boundary ({to_hex_string(size_of_image)}).")
                
                # Use Python's lzma module to decompress data
                # Note: We need to construct a properly formatted LZMA stream
                lc = lzma_props_data[0] % 9
                lp = (lzma_props_data[0] // 9) % 5
                pb = lzma_props_data[0] // 45
                dict_size = int.from_bytes(lzma_props_data[1:5], byteorder='little')
                
                # Build LZMA compression filter
                filters = [
                    {
                        "id": lzma.FILTER_LZMA1,
                        "dict_size": dict_size,
                        "lc": lc,
                        "lp": lp,
                        "pb": pb
                    }
                ]
                
                # Create an LZMA decompressor
                decompressor = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
                
                # Decompress data
                try:
                    decompressed_data = decompressor.decompress(compressed_data)
                    
                    # Write decompressed data to target location
                    available_space = size_of_image - uncompressed_target_rva
                    if len(decompressed_data) <= available_space:
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+len(decompressed_data)] = decompressed_data
                    else:
                        print(f"Warning: Block {block_idx}: Decompressed data size exceeds available space in image")
                        # Only write data that can fit
                        unpacked_image[uncompressed_target_rva:uncompressed_target_rva+available_space] = decompressed_data[:available_space]
                    
                    print(f"Block {block_idx}: Decompressed. Output size={len(decompressed_data)}")
                
                except lzma.LZMAError as e:
                    raise RuntimeError(f"LZMA decompression error: {str(e)}")
        
        except Exception as e:
            raise RuntimeError(f"Error processing LZMA data: {str(e)}")
    
    return bytes(unpacked_image)


def derive_key_hints(image, known_plaintext, rva):
    for offset in range(0x100):
        key_leak = 0
        key_mask = 0
        prev_byte = None
        found = True
        for j, expected in enumerate(known_plaintext):
            n = offset + j
            if rva + n >= len(image):
                found = False
                break
            byte = image[rva + n] ^ expected
            byte = (byte - n) & 0xFF
            if prev_byte is not None and (prev_byte & 0x7F) != (byte >> 1):
                found = False
                break
            key_leak |= ror32(byte, n)
            key_mask |= ror32(0xFF, n)
            prev_byte = byte
        if found:
            return offset, key_leak, key_mask
    raise ValueError('no consistent offset found for known plaintext')


def find_key(pe):
    image = pe.get_memory_mapped_image()
    mapped = MappedRanges(pe)
    vmp_section: pefile.SectionStructure = find_vmp_section(pe)

    sec_start = vmp_section.VirtualAddress
    sec_size = max(vmp_section.Misc_VirtualSize, vmp_section.SizeOfRawData)
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

    rva_dll_name = _U32.unpack_from(image, best_rva)[0]
    rva_api_name = _U32.unpack_from(image, best_rva + 4)[0]

    try:
        offset, key_leak, key_mask = derive_key_hints(image, KNOWN_PLAINTEXT, rva_dll_name)
    except ValueError as exc:
        print(exc)
        return 0
    print('found offset', offset, hex(key_leak), hex(key_mask))
    pos = code.find(b'\xB8')
    while pos != -1 and pos + 5 <= len(code):
        ea = sec_start + pos
        # mov eax, key
        key = _U32.unpack_from(code, pos + 1)[0]
        if (key & key_mask) == key_leak:
            try:
                dll_name = decrypt_string(image, rva_dll_name, key).decode()
                api_name = decrypt_string(image, rva_api_name, key).decode()
                if dll_name and dll_name.isprintable() and api_name and api_name.isprintable():
                    return key
            except Exception:
                pass
        pos = code.find(b'\xB8', pos + 1)
    return 0


def parse_va_list(s):
    """Parse a comma-separated list of hex addresses (image-base VAs)."""
    return [int(x, 0) for x in s.split(',') if x.strip()]


def find_import_descriptors(pe, key, section_chars):
    """Locate the VMP import-descriptor block.

    Returns ``(dll_info_rva, [(dll_name, [(api, slot_rva, key), ...]), ...])``
    or ``(None, [])`` when nothing valid is found.
    """
    vmp_section = find_vmp_section(pe, section_chars)
    if vmp_section is None:
        return None, []
    mm = pe.get_memory_mapped_image()
    mapped = MappedRanges(pe)
    sec_start = vmp_section.VirtualAddress
    sec_end = min(sec_start + max(vmp_section.Misc_VirtualSize,
                                  vmp_section.SizeOfRawData), len(mm))
    best_ea, best_count = None, 0
    for ea in find_descriptor_candidates(mm, mapped, sec_start, sec_end):
        count = count_valid_dll_descriptors(mm, mapped, ea)
        if count > best_count:
            best_ea, best_count = ea, count
    if best_ea is None:
        return None, []
    return best_ea, parse_import_descriptors(mm, mapped, key, best_ea)


def build_import_map(pe, key, section_chars):
    """Map IAT slot RVA -> 'DLL!api' using dump_imports' descriptor parser."""
    _, dlls = find_import_descriptors(pe, key, section_chars)
    result = {}
    for dll_name, apis in dlls:
        for api, address, _ in apis:
            if address is not None:
                result[address] = f'{dll_name}!{api}'
    return result


def build_fix_section(pe, dlls, sites):
    """Build the new section blob: import directory + fresh IAT + redirect stubs.

    The import table is emitted in the standard layout -- one descriptor per
    DLL, with contiguous per-DLL ``OriginalFirstThunk``/``FirstThunk`` arrays
    (the loader fills the IAT slots).  Ordinal imports use a real ordinal
    thunk instead of a bogus hint/name string.

    Returns ``(blob, slot_va, stub_va, descriptors_rva, descriptors_size,
    iat_rva, iat_size)``.
    """
    sec_va = pe.OPTIONAL_HEADER.SizeOfImage
    blob = bytearray()

    def alloc(data, align=8):
        off = len(blob)
        blob.extend(data)
        blob.extend(b'\0' * ((-len(blob)) % align))
        return sec_va + off

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
        base = alloc(b'\0' * (8 * len(entries)))
        iat_rva[dll_name] = base
        iat_size += 8 * len(entries)
        for idx, (api, slot) in enumerate(entries):
            slot_va[slot] = base + idx * 8
    iat_start = iat_rva[dll_order[0]] if dll_order else None

    # Redirect stubs for call sites without room for a 6-byte call/jmp.
    stub_va = {}
    for rva, kind, api, slot, size in sites:
        stub = struct.pack('<BB', 0xFF, 0x25) + struct.pack(
            '<i', slot_va[slot] - (sec_va + len(blob) + 6))
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
                arr.extend(struct.pack('<Q', IMAGE_ORDINAL_FLAG64
                                       | int(api.rsplit('_', 1)[1])))
            else:
                hn_rva = alloc(struct.pack('<H', 0) + api.encode('latin-1')
                               + b'\0', align=8)
                arr.extend(struct.pack('<Q', hn_rva))
        arr.extend(b'\0' * 8)
        oft_rva[dll_name] = alloc(bytes(arr), align=8)

    desc_off = len(blob)
    for dll_name in dll_order:
        blob.extend(struct.pack('<5I', oft_rva[dll_name], 0, 0,
                                name_rva[dll_name], iat_rva[dll_name]))
    blob.extend(b'\0' * 20)
    n = sum(len(v) for v in dll_imports.values())
    return (bytes(blob), slot_va, stub_va, sec_va + desc_off,
            20 * (len(dll_order) + 1), iat_start, iat_size)


def add_section(data, pe, blob, name='idata', chars=0xC0000040):
    """Append a new section header + raw data; return the rebuilt PE bytes.

    pefile is a parser and has no add-section API, and ``write()`` would
    re-serialize the whole image (risky for a protected dump), so the new
    IMAGE_SECTION_HEADER is spliced into the raw bytes directly.
    """
    out = bytearray(data)
    nsec = pe.FILE_HEADER.NumberOfSections
    va = pe.OPTIONAL_HEADER.SizeOfImage
    fa = pe.OPTIONAL_HEADER.FileAlignment
    sa = pe.OPTIONAL_HEADER.SectionAlignment
    raw_off = len(data)
    rsize = (len(blob) + fa - 1) // fa * fa

    # Next free slot in the section header table: last header + 40 bytes.
    hdr_off = pe.sections[-1].get_file_offset() + 40
    if hdr_off + 40 > pe.OPTIONAL_HEADER.SizeOfHeaders:
        raise SystemExit('no room in the section header table')
    out[hdr_off: hdr_off + 40] = struct.pack(
        '<8sIIIIIIHHI', name.encode(), len(blob), va, rsize, raw_off,
        0, 0, 0, 0, chars)

    # FILE_HEADER.NumberOfSections (after the 4-byte PE\\0\\0 signature)
    # and OPTIONAL_HEADER.SizeOfImage (fixed at offset 56 in both PE32/PE32+).
    # SizeOfImage must cover the whole new section's virtual extent, not just
    # one SectionAlignment -- otherwise the appended import directory lands
    # outside the image and is ignored by IDA/Windows.
    nt_off = pe.NT_HEADERS.get_file_offset()
    out[nt_off + 4 + 2: nt_off + 4 + 4] = struct.pack('<H', nsec + 1)
    size_of_image = ((va + len(blob) + sa - 1) // sa) * sa
    out[pe.OPTIONAL_HEADER.get_file_offset() + 56:
        pe.OPTIONAL_HEADER.get_file_offset() + 60] = struct.pack('<I', size_of_image)

    out.extend(blob)
    out.extend(b'\0' * (rsize - len(blob)))
    return bytes(out)


def fix_imports(data, pe, key, section_chars, code_rva, internal_stub_rvas=(),
                verbose=False):
    """Rebuild the import table, patch the call sites and write a fixed PE.
    """
    dll_info, dlls = find_import_descriptors(pe, key, section_chars)
    if dll_info is None:
        raise SystemExit('no import descriptors found')
    print(f'import descriptors at {dll_info:#x}, {len(dlls)} DLLs')

    import_map = build_import_map(pe, key, section_chars)
    code_section, code_rva = find_code_section(pe, code_rva)
    sites = classify_sites(pe, import_map, code_section, code_rva,
                           internal_stub_rvas, verbose)
    if not sites:
        raise SystemExit('no import call sites classified')
    print(f'{len(sites)} import call sites classified')

    blob, slot_va, stub_va, desc_rva, desc_size, iat_rva, iat_size = \
        build_fix_section(pe, dlls, sites)
    base = pe.OPTIONAL_HEADER.ImageBase

    out = bytearray(data)
    for rva, kind, api, slot, size in sites:
        at = rva
        if size >= 6:
            opcode = b'\xFF\x15' if kind == 'CALL' else b'\xFF\x25'
            patch = opcode + struct.pack(
                '<i', base + slot_va[slot] - (base + at + 6))
            out[pe.get_offset_from_rva(at):pe.get_offset_from_rva(at) + 6] = patch
        else:
            opcode = b'\xE8' if kind == 'CALL' else b'\xE9'
            patch = opcode + struct.pack(
                '<i', base + stub_va[(api, slot)] - (base + at + 5))
            out[pe.get_offset_from_rva(at):pe.get_offset_from_rva(at) + 5] = patch


    out = bytearray(add_section(bytes(out), pe, blob, chars=0xE0000040))
    dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].get_file_offset()
    struct.pack_into('<II', out, dd, desc_rva, desc_size)
    iat_dd = pe.OPTIONAL_HEADER.DATA_DIRECTORY[12].get_file_offset()
    struct.pack_into('<II', out, iat_dd, iat_rva, iat_size)

    print(f'import dir rva={desc_rva:#x} '
          f'size={desc_size:#x} ({sum(len(a) for _, a in dlls)} imports)')
    return bytes(out)


def find_code_section(pe, code_rva=None):
    """Return (section, rva) of the code to scan.

    Defaults to the first executable code section; override with ``code_rva``.
    """
    if code_rva is not None:
        section = pe.get_section_by_rva(code_rva)
        if section is not None:
            return section, code_rva
        raise SystemExit(f'no section contains rva {code_rva:#x}')
    for section in pe.sections:
        if section.IMAGE_SCN_MEM_EXECUTE and section.IMAGE_SCN_CNT_CODE:
            return section, section.VirtualAddress
    raise SystemExit('no executable code section found')


# def hook_code(uc, address, size, userdata):
#     print(hex(address))
#     pass


def hook_mem_read(uc, access, address, size, value, userdata):
    # Only fires for reads in the mapped image range; the stack lives at
    # 0x100000, outside that range, so stack reads never reach this hook.
    userdata.read_record_list.append(address)


class Emu:
    def __init__(self, pe: pefile.PE, import_map=None, verbose=False):
        self.import_map = import_map or {}
        self.verbose = verbose
        base = pe.OPTIONAL_HEADER.ImageBase
        uc = Uc(UC_ARCH_X86, UC_MODE_64)
        for section in pe.sections:
            if not section.SizeOfRawData:
                continue
            data = pe.get_data(section.VirtualAddress, section.SizeOfRawData)
            size = (section.SizeOfRawData + 0xFFF) & ~0xFFF

            prot = UC_PROT_NONE
            if section.IMAGE_SCN_MEM_READ:
                prot |= UC_PROT_READ
            if section.IMAGE_SCN_MEM_WRITE:
                prot |= UC_PROT_WRITE
            if section.IMAGE_SCN_MEM_EXECUTE:
                prot |= UC_PROT_EXEC

            uc.mem_map(base + section.VirtualAddress, size, prot)
            uc.mem_write(base + section.VirtualAddress, data)

        self.read_record_list = []
        self.stack_address = 0x100000
        self.stack_size = 0x20000
        self.stack_init = self.stack_address + self.stack_size - 0x1000
        uc.mem_map(self.stack_address, self.stack_size)
        uc.reg_write(UC_X86_REG_RSP, self.stack_init)
        # uc.hook_add(UC_HOOK_CODE, hook_code, self)
        uc.hook_add(UC_HOOK_MEM_READ, hook_mem_read, self,
                    base, base + pe.OPTIONAL_HEADER.SizeOfImage)
        self.uc_context = uc.context_save()
        
        self.pe = pe
        self.uc = uc

    def reset(self):
        """Reset per-run state so one instance can be reused across sites."""
        self.read_record_list.clear()
        self.uc.context_restore(self.uc_context)
        self.uc.mem_write(self.stack_address, b'\0' * self.stack_size)

    def resolve_import(self, address):
        info = self.import_map.get(address - self.pe.OPTIONAL_HEADER.ImageBase)
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
                self.last['rip'] = self.uc.reg_read(UC_X86_REG_RIP)
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

        rsp = self.uc.reg_read(UC_X86_REG_RSP)
        delta_rsp = rsp - self.stack_init

        try:
            prev_code = self.uc.mem_read(address - 1, 1)[0]
        except UcError:
            prev_code = None
        is_push_reg = prev_code is not None and 0x50 <= prev_code <= 0x57

        size = 6
        return_address = struct.unpack('<Q', self.uc.mem_read(rsp, 8))[0]
        if return_address:
            delta_rip = return_address - address
            if delta_rip == 6 and delta_rsp == -8:
                kind = 'CALL'
            elif delta_rip == 5 and delta_rsp == 0:
                if not is_push_reg:
                    self.last['reason'] = ('return addr +5, rsp balanced, but '
                                           'no preceding push register')
                    return
                kind = 'CALL'
                address -= 1
            elif delta_rip == 5 and delta_rsp == -8:
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
            elif delta_rsp == 8 and is_push_reg:
                kind = 'JMP'
                address -= 1
            else:
                self.last['reason'] = (f'no return address, '
                                       f'delta_rsp={delta_rsp:#x}')
                return
        self.last['slot'] = read_addr - self.pe.OPTIONAL_HEADER.ImageBase
        return address, kind, target, size


def classify_sites(pe, import_map, code_section, code_rva, internal_stub_rvas=(),
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
    base = pe.OPTIONAL_HEADER.ImageBase
    code = pe.get_data(code_section.VirtualAddress, code_section.SizeOfRawData)
    internal = set(internal_stub_rvas)
    emu = Emu(pe, import_map, verbose)
    sites = []
    i = code.find(b'\xe8')
    while i != -1:
        rva = code_rva + i
        try:
            dst = rva + struct.unpack('<i', code[i + 1:i + 5])[0] + 5
        except struct.error:
            i = code.find(b'\xe8', i + 1)
            continue
        dst_section = pe.get_section_by_rva(dst)
        cross_section = (dst_section and dst_section != code_section and
                         (dst_section.Characteristics & IMAGE_SCN_MEM_EXECUTE))
        internal_stub = dst_section == code_section and dst in internal
        if not (cross_section or internal_stub):
            i = code.find(b'\xe8', i + 1)
            continue
        if verbose:
            loc = dst_section.Name.decode('latin-1', 'ignore') if dst_section else '?'
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
    parser.add_argument('file', help='path to the VMProtect-protected PE file')
    parser.add_argument('-k', '--key', type=lambda s: int(s, 0), default=0,
                        help='string decryption key (default: 0)')
    parser.add_argument('--section-chars', type=lambda s: int(s, 0), default=0x68000060,
                        help='characteristics of the VMP section (default: 0x68000060)')
    parser.add_argument('--code-rva', type=lambda s: int(s, 0), default=None,
                        help='code section RVA to scan (default: first executable code section)')
    parser.add_argument('--internal-stubs', type=parse_va_list, default=[],
                        metavar='ADDR',
                        help='comma-separated address(es) of import stubs '
                             'VMProtect reused inside the code section; call '
                             'sites whose first jump lands on them are '
                             'emulated too. Each entry may be an image-base VA '
                             'or an RVA; values >= image base are treated as '
                             'VAs, smaller ones as RVAs '
                             '(e.g. --internal-stubs=0x140001AB4,0x1AB4)')
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
        
        # Perform unpacking
        print("Unpacking...")
        unpacked_data = unpack_pe(packed_data)
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

        print("Fixing imports...")
        pe = pefile.PE(data=unpacked_data, fast_load=True)
        
        if pe.FILE_HEADER.Machine != pefile.MACHINE_TYPE["IMAGE_FILE_MACHINE_AMD64"]:
            print("Import table repair only supports AMD64 binaries")
            return 0
        base = pe.OPTIONAL_HEADER.ImageBase
        key = args.key if args.key else find_key(pe)
        print('key:', hex(key))
        if not key:
            return 0
        internal_rvas = [va - base if va >= base else va for va in args.internal_stubs]
        output_filepath = args.file + '.fixed'
        output_data = fix_imports(unpacked_data, pe, key, args.section_chars, 
                                    args.code_rva, internal_rvas, args.verbose)
        with open(output_filepath, 'wb') as f:
            f.write(output_data)
        print(f"Fixed: {output_filepath}")
        return 0
    except Exception as e:
        print(f"Exception occurred during unpacking: {str(e)}")
        return 1

if __name__ == "__main__":
    sys.exit(main())