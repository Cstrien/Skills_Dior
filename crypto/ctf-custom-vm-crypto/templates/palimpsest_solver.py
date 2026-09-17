#!/usr/bin/env python3
"""
Palimpsest-style Custom VM Crypto Solver Template
=================================================
Reusable solver for CTF challenges with custom VMs encoding crypto operations.
Adapt the VM opcodes, cell format, and crypto transform to match your challenge.

Usage:
  python3 solver.py --pal <program_file> --compute-seal --host-profile <profile.bin>
  python3 solver.py --pal <program_file> --recover-soul
  python3 solver.py --pal <program_file> --decrypt <encrypted_file> --seal <hex> --soul <hex> --host-identity <identity.bin>
"""

import argparse
import hashlib
import hmac
import struct
import sys
from dataclasses import dataclass, field
from typing import List, Dict, Optional

# ─── CRC helpers ──────────────────────────────────────────────────────────

def crc8_atm(data: bytes) -> int:
    crc = 0
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = ((crc << 1) ^ 0x07) & 0xFF if crc & 0x80 else (crc << 1) & 0xFF
    return crc

def crc32_ieee(data: bytes) -> int:
    import zlib
    return zlib.crc32(data) & 0xFFFFFFFF

# ─── Data structures ──────────────────────────────────────────────────────
# Adapt these to your challenge's binary format

@dataclass
class PalCell:
    rune: int; op_a: int; op_b: int; imm: int; mode: int; aux: int; crc: int; low24: int

@dataclass
class MicroTemplate:
    enc_op: int; dst_sel: int; src_a_sel: int; src_b_sel: int; imm_sel: int; flags: int; literal: int

@dataclass
class LexiconEntry:
    micro_count: int; phase_delta: int; move_policy: int
    micros: List[MicroTemplate]; entry_crc32: int

# ─── Binary parser ─────────────────────────────────────────────────────────
# Adapt parse_program() to your challenge's binary format

def parse_program(filepath):
    """Parse challenge binary format. Returns program object with grid, lexicons, portals, mutations."""
    with open(filepath, 'rb') as f:
        data = f.read()
    # TODO: Parse header, grid, lexicons, portals, mutations
    # TODO: Verify all CRCs
    raise NotImplementedError("Adapt to your challenge's binary format")

# ─── Codec table extraction from stripped ELF ──────────────────────────────

def extract_codec_tables(binary_path):
    """Find codec tables in stripped ELF by structural signature."""
    with open(binary_path, 'rb') as f:
        binary = f.read()
    # Pattern: 64-byte array where sorted == sorted(list(range(16))*4)
    expected = sorted(list(range(16)) * 4)
    for i in range(len(binary) - 196):
        if sorted(list(binary[i:i+64])) == expected:
            # Verify adjacent tables are valid permutations
            if sorted(binary[i+64:i+72]) == list(range(8)):
                # Read all tables sequentially
                off = i
                return {
                    'token_to_rune': list(binary[off:off+64]),
                    'reg_a_pos': list(binary[off+64:off+72]),
                    'reg_b_pos': list(binary[off+72:off+80]),
                    # ... add more tables as needed
                }
    raise ValueError("Codec tables not found")

# ─── VM Emulator ───────────────────────────────────────────────────────────
# Adapt opcodes and execution logic to your challenge

def rol32(val, count):
    count &= 31; val &= 0xFFFFFFFF
    return ((val << count) | (val >> (32 - count))) & 0xFFFFFFFF if count else val

class VMEmulator:
    def __init__(self, prog, enc_to_canonical):
        self.prog = prog
        self.enc_to_can = enc_to_canonical
        self.output = bytearray()
        self.trace = bytearray()

    def run(self, mode=0, soul_candidate=None, host=None):
        """Run VM. Returns (state, seal_hex, output_bytes)."""
        # TODO: Implement execution loop for your challenge's ISA
        # Key steps:
        # 1. Initialize state (position, dir, phase, dialect, regs, memory)
        # 2. For each step: lookup cell, apply mutations, lookup lexicon, dispatch micro-ops
        # 3. Serialize trace bytes according to challenge's trace format
        # 4. Compute seal = SHA-256(trace)
        raise NotImplementedError("Adapt to your challenge's VM")

# ─── Bijective Transform Inverse ──────────────────────────────────────────
# Adapt to your challenge's crypto transform

@dataclass
class TransformParams:
    """Parameters for the challenge's bijective transform."""
    P: List[List[int]]      # Permutations
    xor_key: List[List[int]]  # XOR keys
    add_key: List[List[int]]  # ADD keys
    C: List[List[int]]     # Constants (C0, C1, C2 per round)
    R: List[List[int]]     # Rotation amounts (R0, R1, R2 per round)
    target: bytes           # Expected transform output

def transform_forward(x, params):
    """Forward bijective transform."""
    raise NotImplementedError("Adapt to your challenge's transform")

def transform_inverse(target, params):
    """Algebraic inverse of the bijective transform."""
    raise NotImplementedError("Adapt to your challenge's transform")

# ─── AEAD Decryption ───────────────────────────────────────────────────────

def derive_key(host_identity, seal, soul, salt, program_digest):
    """HKDF-SHA256 key derivation. Adapt info string and IKM format."""
    ikm = b"PREFIX" + struct.pack('<H', len(host_identity)) + host_identity + seal + soul + program_digest
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, b"INFO_STRING\x01", hashlib.sha256).digest()

def decrypt_vault(stub, seal, soul, identity, digest):
    """Decrypt AEAD-encrypted vault file. Adapt cipher, nonce offset, AAD."""
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    salt = stub[60:76]  # Adapt offsets
    nonce = stub[76:88]
    key = derive_key(identity, seal, soul, salt, digest)
    cipher = ChaCha20Poly1305(key)
    aad = stub[:100]
    ct = stub[100:100+struct.unpack_from('<Q', stub, 20)[0]]
    tag = stub[100+ct_len:100+ct_len+16]
    return cipher.decrypt(nonce, ct + tag, aad)

# ─── Main ──────────────────────────────────────────────────────────────────

def main():
    p = argparse.ArgumentParser(description="Custom VM Crypto Solver")
    p.add_argument('--pal', help='Program file path')
    p.add_argument('--binary', help='Stripped ELF binary path')
    p.add_argument('--compute-seal', action='store_true')
    p.add_argument('--recover-soul', action='store_true')
    p.add_argument('--decrypt', help='Decrypt encrypted file')
    p.add_argument('--host-profile', help='Host profile blob')
    p.add_argument('--host-identity', help='Host identity blob')
    p.add_argument('--seal', help='Seal hex')
    p.add_argument('--soul', help='Soul hex')
    args = p.parse_args()

    if not args.pal:
        p.print_help(); return

    # Parse program
    prog = parse_program(args.pal)

    # Extract codec tables from binary
    if args.binary:
        codec = extract_codec_tables(args.binary)
        print(f"Codec tables: {len(codec)} tables extracted")

    if args.compute_seal:
        print("Computing semantic seal...")
        # TODO: Get host profile, run VM, compute seal

    if args.recover_soul:
        print("Recovering soul via algebraic inversion...")
        # TODO: Trace VM in probe mode, extract params, invert transform

    if args.decrypt:
        print(f"Decrypting {args.decrypt}...")
        # TODO: Derive key, decrypt AEAD

if __name__ == '__main__':
    main()
