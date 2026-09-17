# Palimpsest: The Archivist — Worked Solution (Team 15)

## Challenge Structure
- `palimpsest` — ELF 64-bit stripped, dynamically linked (libxml2, openssl)
- `archivist.svg` — 1056×1056 SVG, program encoded as vector geometry
- `archivist.private.pal` — Binary PAL1 format (private, organizer only)

## Extracted Values (Team 15)

### Codec Tables (file offset 0x2e76340)
```
PAL_TOKEN_TO_RUNE[64]: [3,1,8,2,6,8,15,0,3,10,3,7,15,14,2,5,0,13,9,7,15,13,9,7,11,6,6,6,12,2,4,1,4,14,10,8,1,14,0,1,11,10,0,15,13,12,3,7,12,5,12,2,13,8,14,11,5,9,9,10,11,4,5,4]
PAL_REG_A_POS_TO_VALUE[8]: [0,4,7,2,5,3,6,1]
PAL_REG_B_POS_TO_VALUE[8]: [5,6,3,2,7,4,0,1]
PAL_MODE_RADIUS_TO_VALUE[4]: [3,2,0,1]
```

### Opcode Mapping (encoded -> canonical)
```
0x8d->0x00(NOP) 0x83->0x01(CONST) 0xba->0x02(MOV) 0x7d->0x03(XOR)
0x34->0x04(ADD) 0x0a->0x05(AND) 0x51->0x06(ROL) 0x0b->0x07(SHR)
0x6f->0x08(LOAD8) 0xfd->0x09(STORE8) 0x97->0x0c(QUERY) 0xb1->0x0d(EMIT)
0xf3->0x0e(TURN) 0x4d->0x0f(BRANCH) 0x69->0x10(PORTAL) 0x6c->0x11(DIALECT)
0xf7->0x12(MUTATE) 0x5b->0x13(HALT)
```

### .pal Header
```
Grid: 32x32, Entry: (25,16) dir=2(S), Phase:0, Dialect:1
Program ID: 0x50414c494d50535b
Max steps: 1000, Mutations: 3
Portals: 4 pairs, All CRC verified
```

### SoulTransformV1 Parameters
```
Round 0:
  P[0] = [6, 5, 8, 2, 9, 0, 11, 7, 4, 10, 1, 3]
  xor_key[0] = [0xe1, 0x34, 0x8f, 0x23, 0x59, 0x5a, 0x22, 0xb7, 0x30, 0xa4, 0x76, 0x29]
  add_key[0] = [0xca, 0x56, 0x1b, 0x23, 0xdd, 0x57, 0x42, 0x1c, 0xf7, 0x95, 0x06, 0x3d]
  C0[0] = 0x461cfb23, C1[0] = 0xc038885d, C2[0] = 0xc9822815
  R0[0] = 18 (15+3), R1[0] = 7, R2[0] = 28 (15+13)

Round 1:
  P[1] = [9, 1, 11, 0, 8, 2, 5, 6, 7, 4, 10, 3]
  xor_key[1] = [0x74, 0x5f, 0x73, 0x29, 0x63, 0x45, 0xa1, 0x52, 0xe6, 0x76, 0x0c, 0xf3]
  add_key[1] = [0x0f, 0xc0, 0x91, 0xff, 0x4a, 0x3b, 0xdc, 0x04, 0xd6, 0x95, 0xd7, 0x8e]
  C0[1] = 0xfc33507a, C1[1] = 0x911edb3f, C2[1] = 0xf23fb36a
  R0[1] = 26 (15+11), R1[1] = 18 (15+3), R2[1] = 27 (15+12)

target = 8b908a0ba43419c5f5aa2a0d
```

### Results
```
SOUL: 490e40098c77062e5479b6e7
SEAL: 866c41ffa66de8c42b3dcb33b45a62f0e37a67c09251b77a1e20727fe90d3405
Run Mode output: "THE ARCHIVIST IS AWAKE.\n\n  .##..#..\n  ##..###.\n  .#.#..#.\n"
Probe Mode output (with correct soul): "THE PRIVATE NAME RESONATES."
```

## How 32-bit Constants Were Extracted

The C0/C1/C2 constants are not single CONST operations — they're built byte-by-byte:
```
CONST R5, 0x46    ; R5 = 0x46
ROL R5, 8         ; R5 = 0x4600
CONST R6, 0x1c    ; 
ADD R5, R6        ; R5 = 0x461c
ROL R5, 8         ; R5 = 0x461c00
CONST R6, 0xfb    ;
ADD R5, R6        ; R5 = 0x461cfb
ROL R5, 8         ; R5 = 0x461cfb00
CONST R6, 0x23    ;
ADD R5, R6        ; R5 = 0x461cfb23 = C0[0]
```
Pattern: CONST(byte0) -> ROL(8) -> CONST(byte1) -> ADD -> ROL(8) -> CONST(byte2) -> ADD -> ROL(8) -> CONST(byte3) -> ADD
Final = (byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3

## How Rotation Amounts Were Extracted

ROL uses aux_nibble selector (4 bits, max 15). Rotations > 15 split across multiple ROLs:
```
ROL R6, 15    ; first part
ROL R6, 3     ; second part
-> total = 18
```
Sum all consecutive ROL operations on the same register to get the actual rotation.

## Execution Trace Pattern (Soul Chamber)

Round 0 (base_src=0x00, base_dst=0x10):
1. CONST R1=0 (clear address register)
2. 12 times: LOAD8 R2=mem[base_src+P[0][i]], CONST R3=xor_key, XOR R2^=R3, CONST R3=add_key, ADD R2+=R3, STORE8 mem[base_dst+i]=R2
   - NOTE: TURN operations may interrupt this pattern (route zigzag). Skip TURNs when extracting.
3. Load 3 words from base_dst (LOAD8+ROL8+ADD pattern, 10 ops per word)
4. Build C0 into R5 (CONST+ROL8+ADD chain), MOV R6=R2, ADD R6+=R5, ROL R6 by R0[0], XOR R3^=R6
5. Build C1 into R5, MOV R6=R3, XOR R6^=R5, ROL R6 by R1[0], ADD R4+=R6
6. Build C2 into R5, MOV R6=R4, ADD R6+=R5, ROL R6 by R2[0], XOR R2^=R6
7. Store w0,w1,w2 back to base_dst (STORE8 + ROL pattern to extract bytes)

Round 1 (base_src=0x10, base_dst=0x30): same structure with round 1 params.

Target comparison: CONST R1=0, CONST R5=0, then 12 times: LOAD8 R2=mem[0x30+i], CONST R3=target[i], XOR R2^=R3, ADD R5+=R2
