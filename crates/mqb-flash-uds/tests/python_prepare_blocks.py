#!/usr/bin/env python3
"""
Run the Python VW_Flash pipeline on tune.bin and save intermediate outputs
for comparison with the Rust implementation.

Performs the same full-flash preparation as VW_Flash:
  1. Extract raw block bytes from the full binary
  2. Apply CBOOT patch (sample-mode needle replacement) to block 1
  3. Fix Simos CRC32 checksums for all blocks (after patching CBOOT)
  4. LZSS-compress each block
  5. AES-128-CBC encrypt each block

Outputs (in the specified output directory):
  block_N_raw.bin       — raw block bytes after CBOOT patch + checksum fix
  block_N_compressed.bin — after LZSS compression
  block_N_encrypted.bin  — after AES-128-CBC encryption

Usage:
    uv run --with pycryptodome python python_prepare_blocks.py <tune.bin> <output_dir>
"""

import os
import struct
import subprocess
import sys

# ── Simos18 configuration (matches modules/simos18.py) ──────────────────────

BINFILE_OFFSETS = {1: 0x1C000, 2: 0x40000, 3: 0x140000, 4: 0x280000, 5: 0x200000}
BLOCK_LENGTHS  = {1: 0x23E00, 2: 0xFFC00, 3: 0xBFC00,  4: 0x7FC00,  5: 0x7FC00}

# Base addresses for each block (absolute ECU addresses)
BASE_ADDRESSES = {
    1: 0x8001C000, 2: 0x80040000, 3: 0x80140000, 4: 0x80880000, 5: 0xA0800000,
    6: 0x80840000,  # CBOOT_TEMP
}

# Checksum header location within each block
CHECKSUM_BLOCK_LOCATION = {1: 0x300, 2: 0x300, 3: 0x0, 4: 0x0, 5: 0x300, 6: 0x340}

S18_KEY = bytes.fromhex("98D31202E48E3854F2CA561545BA6F2F")
S18_IV  = bytes.fromhex("E7861278C508532798BCA4FE451D20D1")

LZSS_EXE = os.path.join(
    os.path.dirname(__file__),
    "..", "..", "..", "..",  # up to VW_Flash_Rewrite
    "VW_Flash", "lib", "lzss", "lzss.exe",
)

# CBOOT patch needle and replacement (same as VW_Flash/lib/patch_cboot.py)
CBOOT_NEEDLE = bytes.fromhex("DA003C02DA0102F2")
CBOOT_PATCH  = bytes.fromhex("0000000000DA0102F2"[:16])  # 8 bytes

# ── Helpers ──────────────────────────────────────────────────────────────────

def patch_cboot(cboot_binary: bytes) -> bytes:
    """Apply the sample-mode CBOOT patch (same logic as VW_Flash)."""
    data = bytearray(cboot_binary)
    first = data.find(CBOOT_NEEDLE)
    second = data.find(CBOOT_NEEDLE, first + len(CBOOT_NEEDLE))
    third = data.find(CBOOT_NEEDLE, second + len(CBOOT_NEEDLE))
    assert first != -1 and second != -1, "CBOOT needle not found twice"
    assert third == -1, "CBOOT needle found more than twice"
    patch = bytes.fromhex("00000000DA0102F2")
    data[first : first + len(CBOOT_NEEDLE)] = patch
    data[second : second + len(CBOOT_NEEDLE)] = patch
    print(f"  CBOOT patched at offsets 0x{first:X} and 0x{second:X}", file=sys.stderr)
    return bytes(data)


# Simos CRC32 table — non-reflected MSB-first, poly 0x04C11DB7, init 0
# (same as VW_Flash/lib/fastcrc.py)
CRC_TABLE = [
    0x00000000, 0x04C11DB7, 0x09823B6E, 0x0D4326D9, 0x130476DC, 0x17C56B6B, 0x1A864DB2, 0x1E475005,
    0x2608EDB8, 0x22C9F00F, 0x2F8AD6D6, 0x2B4BCB61, 0x350C9B64, 0x31CD86D3, 0x3C8EA00A, 0x384FBDBD,
    0x4C11DB70, 0x48D0C6C7, 0x4593E01E, 0x4152FDA9, 0x5F15ADAC, 0x5BD4B01B, 0x569796C2, 0x52568B75,
    0x6A1936C8, 0x6ED82B7F, 0x639B0DA6, 0x675A1011, 0x791D4014, 0x7DDC5DA3, 0x709F7B7A, 0x745E66CD,
    0x9823B6E0, 0x9CE2AB57, 0x91A18D8E, 0x95609039, 0x8B27C03C, 0x8FE6DD8B, 0x82A5FB52, 0x8664E6E5,
    0xBE2B5B58, 0xBAEA46EF, 0xB7A96036, 0xB3687D81, 0xAD2F2D84, 0xA9EE3033, 0xA4AD16EA, 0xA06C0B5D,
    0xD4326D90, 0xD0F37027, 0xDDB056FE, 0xD9714B49, 0xC7361B4C, 0xC3F706FB, 0xCEB42022, 0xCA753D95,
    0xF23A8028, 0xF6FB9D9F, 0xFBB8BB46, 0xFF79A6F1, 0xE13EF6F4, 0xE5FFEB43, 0xE8BCCD9A, 0xEC7DD02D,
    0x34867077, 0x30476DC0, 0x3D044B19, 0x39C556AE, 0x278206AB, 0x23431B1C, 0x2E003DC5, 0x2AC12072,
    0x128E9DCF, 0x164F8078, 0x1B0CA6A1, 0x1FCDBB16, 0x018AEB13, 0x054BF6A4, 0x0808D07D, 0x0CC9CDCA,
    0x7897AB07, 0x7C56B6B0, 0x71159069, 0x75D48DDE, 0x6B93DDDB, 0x6F52C06C, 0x6211E6B5, 0x66D0FB02,
    0x5E9F46BF, 0x5A5E5B08, 0x571D7DD1, 0x53DC6066, 0x4D9B3063, 0x495A2DD4, 0x44190B0D, 0x40D816BA,
    0xACA5C697, 0xA864DB20, 0xA527FDF9, 0xA1E6E04E, 0xBFA1B04B, 0xBB60ADFC, 0xB6238B25, 0xB2E29692,
    0x8AAD2B2F, 0x8E6C3698, 0x832F1041, 0x87EE0DF6, 0x99A95DF3, 0x9D684044, 0x902B669D, 0x94EA7B2A,
    0xE0B41DE7, 0xE4750050, 0xE9362689, 0xEDF73B3E, 0xF3B06B3B, 0xF771768C, 0xFA325055, 0xFEF34DE2,
    0xC6BCF05F, 0xC27DEDE8, 0xCF3ECB31, 0xCBFFD686, 0xD5B88683, 0xD1799B34, 0xDC3ABDED, 0xD8FBA05A,
    0x690CE0EE, 0x6DCDFD59, 0x608EDB80, 0x644FC637, 0x7A089632, 0x7EC98B85, 0x738AAD5C, 0x774BB0EB,
    0x4F040D56, 0x4BC510E1, 0x46863638, 0x42472B8F, 0x5C007B8A, 0x58C1663D, 0x558240E4, 0x51435D53,
    0x251D3B9E, 0x21DC2629, 0x2C9F00F0, 0x285E1D47, 0x36194D42, 0x32D850F5, 0x3F9B762C, 0x3B5A6B9B,
    0x0315D626, 0x07D4CB91, 0x0A97ED48, 0x0E56F0FF, 0x1011A0FA, 0x14D0BD4D, 0x19939B94, 0x1D528623,
    0xF12F560E, 0xF5EE4BB9, 0xF8AD6D60, 0xFC6C70D7, 0xE22B20D2, 0xE6EA3D65, 0xEBA91BBC, 0xEF68060B,
    0xD727BBB6, 0xD3E6A601, 0xDEA580D8, 0xDA649D6F, 0xC423CD6A, 0xC0E2D0DD, 0xCDA1F604, 0xC960EBB3,
    0xBD3E8D7E, 0xB9FF90C9, 0xB4BCB610, 0xB07DABA7, 0xAE3AFBA2, 0xAAFBE615, 0xA7B8C0CC, 0xA379DD7B,
    0x9B3660C6, 0x9FF77D71, 0x92B45BA8, 0x9675461F, 0x8832161A, 0x8CF30BAD, 0x81B02D74, 0x857130C3,
    0x5D8A9099, 0x594B8D2E, 0x5408ABF7, 0x50C9B640, 0x4E8EE645, 0x4A4FFBF2, 0x470CDD2B, 0x43CDC09C,
    0x7B827D21, 0x7F436096, 0x7200464F, 0x76C15BF8, 0x68860BFD, 0x6C47164A, 0x61043093, 0x65C52D24,
    0x119B4BE9, 0x155A565E, 0x18197087, 0x1CD86D30, 0x029F3D35, 0x065E2082, 0x0B1D065B, 0x0FDC1BEC,
    0x3793A651, 0x3352BBE6, 0x3E119D3F, 0x3AD08088, 0x2497D08D, 0x2056CD3A, 0x2D15EBE3, 0x29D4F654,
    0xC5A92679, 0xC1683BCE, 0xCC2B1D17, 0xC8EA00A0, 0xD6AD50A5, 0xD26C4D12, 0xDF2F6BCB, 0xDBEE767C,
    0xE3A1CBC1, 0xE760D676, 0xEA23F0AF, 0xEEE2ED18, 0xF0A5BD1D, 0xF464A0AA, 0xF9278673, 0xFDE69BC4,
    0x89B8FD09, 0x8D79E0BE, 0x803AC667, 0x84FBDBD0, 0x9ABC8BD5, 0x9E7D9662, 0x933EB0BB, 0x97FFAD0C,
    0xAFB010B1, 0xAB710D06, 0xA6322BDF, 0xA2F33668, 0xBCB4666D, 0xB8757BDA, 0xB5365D03, 0xB1F740B4,
]


def crc32_simos(data: bytes) -> int:
    """Non-reflected MSB-first CRC32 (Simos variant)."""
    crc = 0
    for byte in data:
        idx = ((crc >> 24) & 0xFF) ^ byte
        crc = ((crc << 8) & 0xFFFFFF00) ^ CRC_TABLE[idx]
    return crc


def fix_simos_checksum(block_data: bytes, block_num: int) -> bytes:
    """Validate and fix Simos CRC32 checksum for a block (same as VW_Flash checksum.validate)."""
    checksum_loc = CHECKSUM_BLOCK_LOCATION[block_num]
    base_address = BASE_ADDRESSES[block_num]

    stored = struct.unpack_from("<I", block_data, checksum_loc + 4)[0]
    area_count = block_data[checksum_loc + 8]

    addresses = []
    for i in range(area_count * 2):
        abs_addr = struct.unpack_from("<I", block_data, checksum_loc + 12 + i * 4)[0]
        addresses.append(abs_addr - base_address)

    checksum_data = bytearray()
    for i in range(0, len(addresses), 2):
        checksum_data += block_data[addresses[i] : addresses[i + 1] + 1]

    calculated = crc32_simos(checksum_data)

    if calculated == stored:
        print(f"  Block {block_num} checksum: valid (0x{stored:08X})", file=sys.stderr)
        return block_data
    else:
        fixed = bytearray(block_data)
        fixed[checksum_loc + 4 : checksum_loc + 8] = struct.pack("<I", calculated)
        print(
            f"  Block {block_num} checksum: fixed (0x{stored:08X} → 0x{calculated:08X})",
            file=sys.stderr,
        )
        return bytes(fixed)


def lzss_compress(data: bytes) -> bytes:
    """Call the same LZSS binary that VW_Flash uses."""
    exe = os.path.normpath(LZSS_EXE)
    assert os.path.isfile(exe), f"LZSS binary not found: {exe}"
    p = subprocess.run(
        [exe, "-s"],
        input=data,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    if p.returncode != 0:
        raise RuntimeError(f"lzss.exe failed: {p.stderr.decode()}")
    return p.stdout


def aes_encrypt(data: bytes) -> bytes:
    """AES-128-CBC encrypt with Simos18 key/IV (same as VW_Flash)."""
    import Crypto.Cipher.AES
    cipher = Crypto.Cipher.AES.new(S18_KEY, Crypto.Cipher.AES.MODE_CBC, S18_IV)
    return cipher.encrypt(data)


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <tune.bin> <output_dir>", file=sys.stderr)
        sys.exit(1)

    tune_path = sys.argv[1]
    out_dir   = sys.argv[2]
    os.makedirs(out_dir, exist_ok=True)

    data = bytearray(open(tune_path, "rb").read())
    assert len(data) == 4_194_304, f"Expected 4 MB, got {len(data)}"

    # ── Step 1: Apply CBOOT patch to the full binary ────────────────────────
    cboot_offset = BINFILE_OFFSETS[1]
    cboot_length = BLOCK_LENGTHS[1]
    cboot_raw = bytes(data[cboot_offset : cboot_offset + cboot_length])
    cboot_patched = patch_cboot(cboot_raw)
    data[cboot_offset : cboot_offset + cboot_length] = cboot_patched

    # ── Step 2: Extract blocks and fix checksums ────────────────────────────
    blocks = {}
    for block_num in sorted(BLOCK_LENGTHS):
        offset = BINFILE_OFFSETS[block_num]
        length = BLOCK_LENGTHS[block_num]
        raw = bytes(data[offset : offset + length])
        assert len(raw) == length
        # Fix Simos CRC32 checksum (CBOOT checksum will be invalidated by patch)
        raw = fix_simos_checksum(raw, block_num)
        # CBOOT has a second checksum header (CBOOT_TEMP at 0x340)
        if block_num == 1:
            raw = fix_simos_checksum(raw, 6)  # 6 = CBOOT_TEMP
        blocks[block_num] = raw

    # ── Step 3: Compress and encrypt each block ─────────────────────────────
    for block_num in sorted(BLOCK_LENGTHS):
        raw = blocks[block_num]

        print(f"Block {block_num}: raw={len(raw)}", end="", file=sys.stderr)

        compressed = lzss_compress(raw)
        print(f" → compressed={len(compressed)}", end="", file=sys.stderr)

        encrypted = aes_encrypt(compressed)
        print(f" → encrypted={len(encrypted)}", file=sys.stderr)

        # Save all three stages
        open(os.path.join(out_dir, f"block_{block_num}_raw.bin"), "wb").write(raw)
        open(os.path.join(out_dir, f"block_{block_num}_compressed.bin"), "wb").write(compressed)
        open(os.path.join(out_dir, f"block_{block_num}_encrypted.bin"), "wb").write(encrypted)

    print("Done.", file=sys.stderr)


if __name__ == "__main__":
    main()
