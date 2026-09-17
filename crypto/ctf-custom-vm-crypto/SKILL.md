---
name: ctf-custom-vm-crypto
description: "Solve CTF challenges with custom VMs encoding crypto ops."
version: 1.0.0
author: curator
license: MIT
metadata:
  hermes:
    tags: [ctf, crypto, reverse-engineering, vm, custom-isa, bijective-transform, hkdf, chacha20poly1305]
    related_skills: [crypto-ctf-helper, crypto-ctf-workflow, reversing-tools-basic-methods, elf-binary-analysis]
---

# CTF Custom VM Crypto Challenge Solver

Solve challenges where a custom virtual machine encodes cryptographic operations
(visible program as SVG/binary grid), and the solution requires: RE the VM,
extract embedded crypto parameters, algebraically invert bijections, and decrypt
host-bound vault files.

## When to Use

Use this skill when a CTF challenge involves:
- A custom VM/ISA with randomized opcodes per team
- A visual program encoding (SVG geometry, custom binary format)
- Bijective crypto transforms (Feistel, word mixing, byte permutation)
- Host-bound key derivation (HKDF with machine identity)
- AEAD vault encryption (ChaCha20-Poly1305)
- Execution trace hashing (SHA-256 of canonical trace = "seal")
- Any challenge where crypto params are embedded IN the program and must be
  extracted by tracing VM execution rather than reading constants directly

## Methodology (5 Phases)

### Phase 1: Reverse Engineer Binary

1. Parse ELF sections manually (`.text`, `.rodata` offsets/sizes)
2. Find codec tables by structural signature:
   - `TOKEN_TO_RUNE[64]`: sorted(bytes) == sorted(list(range(16))*4)
   - Adjacent tables: verify they're valid permutations (is_perm of 0..n)
3. Extract opcode mapping from lexicon entries:
   - Each rune maps to a canonical opcode (0x00-0x13)
   - The encoded op_id in the lexicon IS the randomized opcode
   - Special runes: D0P0 R6 (2 micro-ops = SHR+ROL), D0P1 R11 (BRANCH), D1P0 R15 (BRANCH)
4. Parse .pal binary format: header (64B), grid (4B/cell), lexicons (48B/entry), portals (12B), mutations (16B)
5. Verify ALL CRCs (CRC-8-ATM for cells, CRC-32 IEEE for header/lexicon/portal/mutation)

### Phase 2: Build VM Emulator

1. Implement state machine: position, dir, phase, dialect, mutation_mask, regs[8], stack[32], memory[256]
2. Implement execution loop: cell lookup then mutation application then lexicon lookup then micro-op dispatch then phase toggle then movement
3. Implement all 20 canonical opcodes (NOP through HALT)
4. Implement dispatch_trace mixing (for seal computation — uses splitmix64-like hash)
5. Handle portals (teleport + advance 1) and mutations (state0/state1 toggle by mask bit)
6. Handle mode split (R7=0 Run, R7=1 Probe)

### Phase 3: Compute Semantic Seal

1. Get host profile: `PALIMPSEST_ALLOW_NON_ROOT=1 ./palimpsest profile` -> PALHOST1 blob
2. Parse PALHOST1 TLV: CPU vendor, count, RAM bucket, disk serial, MAC
3. Run VM in Run Mode (mode=0, R7=0, memory=0)
4. Serialize trace bytes (PALSEAL2 format):
   - Header: "PALSEAL2" + program_id(u64LE) + width + height + mode
   - Per step: step_index(u32LE) + 8 state bytes + rune + micro_count
   - Per micro-op: op_id + dst + src_a + src_b + imm(u32LE) + flags
   - Post-step: 7 state bytes + dispatch_trace(u64LE)
   - Suffix: "PALEND2" + termination_reason + step_count(u32LE)
5. `seal = SHA-256(trace_bytes).hexdigest()`

### Phase 4: Recover Soul (Algebraic Inversion)

1. Run VM in Probe Mode (mode=1, R7=1, memory[0:12]=candidate)
2. Instrument VM to log all CONST, LOAD8, STORE8, ROL operations with step numbers
3. Extract SoulTransformV1 parameters from the execution trace:
   - `P[r][i]`: from LOAD8 address (subtract base_src for that round)
   - `xor_key[r][i]`: CONST value before XOR operation
   - `add_key[r][i]`: CONST value before ADD operation
   - `C0[r], C1[r], C2[r]`: 32-bit constants built from CONST+ROL8+ADD chains
   - `R0[r], R1[r], R2[r]`: rotation amounts from ROL operations (may be split: sum them)
   - `target[12]`: CONST values in the comparison section
4. Verify bijection: forward(inverse(x)) == x for random test inputs
5. `soul = invert_soul_transform(target, params)` — reverse round order, undo triangular mixing, undo byte permutation

### Phase 5: Decrypt Vault

1. Construct PRI1 frame: `b"PRI1" + seal(32B) + soul(12B)` = 48 bytes
2. Get host identity: `sudo ./palimpsest identity` -> PALID2 blob
3. Derive key: HKDF-SHA256(salt=stub[60:76], IKM, info="PALINFO-VAULT-v4")
   - IKM = "PALIKM4" + len(identity) + identity + seal + soul + program_digest
4. Decrypt: ChaCha20-Poly1305(key, nonce=stub[76:88], aad=stub[0:100], ct, tag)
5. Verify stub: magic "SBC2026", version=2, cipher=1, CRC-32 of header, SHA-256(path)

## Key Techniques

### Finding Codec Tables in Stripped ELF
```python
expected = sorted(list(range(16)) * 4)
for i in range(len(binary) - 196):
    if sorted(list(binary[i:i+64])) == expected:
        if is_perm(binary[i+64:i+72], 8):  # reg_a follows token_to_rune
            # Found! Read all 9 tables sequentially from offset i
```

### Extracting 32-bit Constants from ROL+ADD Chains
Constants are built byte-by-byte: CONST(0x46) -> ROL(8) -> CONST(0x1c) -> ADD -> ROL(8) -> ...
Final value: `(b0 << 24) | (b1 << 16) | (b2 << 8) | b3`

### Extracting Rotation Amounts from Multi-ROL
ROL shift limited to 4-bit aux (max 15). Larger rotations split: ROL 15 + ROL 3 = 18. Sum consecutive ROLs.

### SoulTransformV1 Inverse
```python
def soul_inverse(target, params):
    x = target
    for r in (1, 0):
        w0, w1, w2 = struct.unpack('<III', x)
        old_w0 = w0 ^ rol32((w2 + C2[r]) & 0xFFFFFFFF, R2[r])
        old_w2 = (w2 - rol32((w1 ^ C1[r]) & 0xFFFFFFFF, R1[r])) & 0xFFFFFFFF
        old_w1 = w1 ^ rol32((old_w0 + C0[r]) & 0xFFFFFFFF, R0[r])
        y = struct.pack('<III', old_w0, old_w1, old_w2)
        pre_perm = bytearray(12)
        for i in range(12):
            b = ((y[i] - add_key[r][i]) & 0xFF) ^ xor_key[r][i]
            pre_perm[P[r][i]] = b
        x = bytes(pre_perm)
    return x
```

## Pitfalls

1. **Opcode randomization**: Canonical opcodes remapped per-team. Extract from lexicon, don't assume identity.
2. **Layout randomization**: Grid rotated+shifted. Use header's entry_x/y/dir, not source defaults.
3. **Multi-ROL rotations**: Aux nibble max 15. Sum consecutive ROLs for actual rotation.
4. **CONST chains for 32-bit values**: Built from 4 bytes via CONST+ROL8+ADD, not single CONST.
5. **TURN ops interrupt sequences**: Route zigzag TURNs break the 6-op pattern. Account for interleaved TURNs.
6. **Mutation cells**: Track mutation_mask through MUTATE ops; apply state0/state1 to affected cells.
7. **Dialect/phase affects lexicon**: Same rune maps to different opcode in different dialect/phase. Track both.
8. **Host binding**: Seal depends on host profile. Capture from binary or run on same machine.
9. **Root requirement**: Use `PALIMPSEST_ALLOW_NON_ROOT=1` env var for non-root execution.
10. **libxml2 version mismatch**: Binary may need `libxml2.so.2` but system has `.so.16`. Symlink fix.

## See Also

- `references/palimpsest-solution.md` — Worked solution for Palimpsest: The Archivist
- `templates/palimpsest_solver.py` — Complete solver tool template
