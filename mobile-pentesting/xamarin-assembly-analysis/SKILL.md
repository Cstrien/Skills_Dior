---
name: xamarin-assembly-analysis
description: Deep analysis of Xamarin .NET assemblies extracted from APKs — XABA blob parsing, IL decompilation with dnfile, US heap string extraction, hardcoded secret hunting, and linker-merged assembly detection. Use this skill whenever analyzing Xamarin apps and needing to extract .NET DLLs from XABA blobs, decompile IL code without ILSpy/dnSpy, find hardcoded AES keys/API endpoints in .NET assemblies, or detect Xamarin linker assembly merging patterns.
---

# Xamarin Assembly Analysis

Deep analysis of Xamarin .NET assemblies extracted from APK files. Covers XABA blob parsing, IL code decompilation, hardcoded secret extraction, and linker merging detection.

## When to Use This Skill

- Analyzing a Xamarin app APK and finding `assemblies.blob` + `assemblies.manifest`
- `pyxamstore` fails to extract assemblies from XABA blob
- Need to decompile .NET IL code without ILSpy/dnSpy/dotnet tools
- Hunting for hardcoded AES keys, API endpoints, or secrets in .NET assemblies
- Detecting Xamarin linker assembly merging (app logic in framework DLLs)

## XABA Blob Format

The XABA format stores multiple .NET assemblies compressed with LZ4 inside a single blob file.

### Header Structure (52 bytes)

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | magic | `XABA` |
| 0x04 | 4 | version | `uint32 LE` |
| 0x08 | 4 | entry_count | `uint32 LE` |
| 0x0C | 4 | header_size | `uint32 LE` (typically 52) |

### XALZ within XABA

Each assembly entry starts with an `XALZ` marker. **Critical difference from standalone XALZ files:**

| Offset | Size | Field | Description |
|--------|------|-------|-------------|
| 0x00 | 4 | magic | `XALZ` |
| 0x04 | 4 | index | `uint32 LE` — **index into manifest name table**, NOT compressed size |
| 0x08 | 4 | uncompressed_size | `uint32 LE` |
| 0x0C | N | compressed_data | LZ4 block data, runs until **next XALZ marker** or end of blob |

### Manifest Format

`assemblies.manifest` is whitespace-delimited text:
```
Hash 32     Hash 64             Blob ID  Blob idx  Name
0x268d61cd  0x9d94a9fe3e62a95b  000      0000      MyApp.Android
```

Parse the `Blob idx` column to map XALZ entries to assembly names via the index field.

### Extraction Script

```python
import struct, lz4.block, os

def extract_xaba(blob_path, manifest_path, outdir):
    with open(blob_path, 'rb') as f:
        data = f.read()
    
    # Parse manifest names
    names = []
    with open(manifest_path, 'r') as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith('Hash'):
                parts = line.split()
                if len(parts) >= 5:
                    names.append(parts[4])
    
    # Find XALZ markers
    xalz_positions = []
    i = 0
    while i < len(data) - 4:
        if data[i:i+4] == b'XALZ':
            xalz_positions.append(i)
        i += 1
    
    os.makedirs(outdir, exist_ok=True)
    
    for idx, pos in enumerate(xalz_positions):
        index_field = struct.unpack('<I', data[pos+4:pos+8])[0]
        uncomp_size = struct.unpack('<I', data[pos+8:pos+12])[0]
        
        # Compressed data runs until next XALZ or EOF
        if idx + 1 < len(xalz_positions):
            comp_end = xalz_positions[idx + 1]
        else:
            comp_end = len(data)
        
        compressed = data[pos+12:comp_end]
        name = names[index_field] if index_field < len(names) else f'assembly_{idx:03d}'
        
        try:
            decompressed = lz4.block.decompress(compressed, uncompressed_size=uncomp_size)
            if decompressed[:2] == b'MZ':
                with open(os.path.join(outdir, name + '.dll'), 'wb') as f:
                    f.write(decompressed)
                print(f"OK: {name}.dll ({len(decompressed)} bytes)")
        except Exception as e:
            print(f"FAIL: {name}: {e}")
```

## Xamarin Linker Assembly Merging

The Xamarin linker merges app code into framework assemblies to reduce APK size. **The main app logic may NOT be in the assembly named after the app.**

### Detection

- The DLL named after the app (e.g., `MyApp.dll`) is small (10-20KB) — only contains `MainActivity`, resource IDs
- A framework DLL (e.g., `Newtonsoft.Json.dll`) is unusually large (1MB+) — contains the app's TypeDefs
- Search all DLLs for TypeDef names matching the app namespace

### Example

```
LParkingMobile.dll       =  16KB  -> Android shell only (MainActivity, Resource IDs)
Newtonsoft.Json.dll      = 1.3MB  -> Contains ALL app logic (LoginPage, CryptoAesAPI, etc.)
```

**Always check ALL extracted DLLs for app-specific TypeDefs**, not just the one named after the app.

## IL Code Decompilation with dnfile

When ILSpy/dnSpy/dotnet tools are unavailable, use Python `dnfile` library:

```bash
pip install dnfile pefile
```

### Basic Usage

```python
import dnfile, struct

pe = dnfile.dnPE("assembly.dll")
md = pe.net.mdtables

# List all TypeDefs
for t in md.TypeDef:
    name = str(t.TypeName) if hasattr(t, 'TypeName') else ''
    ns = str(t.TypeNamespace) if hasattr(t, 'TypeNamespace') else ''
    print(f"{ns}.{name}")

# List all MethodDefs
for m in md.MethodDef:
    name = str(m.Name) if hasattr(m, 'Name') else ''
    print(f"  {name}")
```

### Extracting IL Code from Methods

```python
def get_il_code(pe, method):
    rva = method.Rva if hasattr(method, 'Rva') else 0
    if rva == 0:
        return None
    
    first_byte = pe.get_data(rva, 1)[0]
    if first_byte & 3 == 2:  # Tiny header
        code_size = first_byte >> 2
        return pe.get_data(rva + 1, code_size)
    elif first_byte & 3 == 3:  # Fat header
        code_size = struct.unpack('<I', pe.get_data(rva + 4, 4))[0]
        return pe.get_data(rva + 12, code_size)
    return None
```

### Extracting String Literals (US Heap)

The User Strings (US) heap stores string literals referenced by `ldstr` IL instructions. **The ldstr token uses byte offsets, not sequential indices.**

```python
us = pe.net.user_strings
us_data = pe.get_data(us.rva, us.sizeof())

def read_us_at_offset(offset):
    if offset >= len(us_data):
        return None
    b = us_data[offset]
    if b < 0x80:
        length = b
        pos = offset + 1
    elif b < 0xC0:
        length = ((b & 0x3F) << 8) | us_data[offset+1]
        pos = offset + 2
    else:
        return None
    if pos + length > len(us_data):
        return None
    if length > 1:
        return us_data[pos:pos+length-1].decode('utf-16-le', errors='replace')
    return None

# Find all ldstr instructions in a method
for m in md.MethodDef:
    il_code = get_il_code(pe, m)
    if not il_code:
        continue
    for i in range(len(il_code) - 4):
        if il_code[i] == 0x72:  # ldstr
            token = struct.unpack('<I', il_code[i+1:i+5])[0]
            if (token >> 24) == 0x70:
                offset = token & 0x00FFFFFF
                s = read_us_at_offset(offset)
                if s:
                    print(f"{m.Name}: [{s}]")
```

### Finding Hardcoded AES Keys

Xamarin apps often store AES keys as static byte arrays in `<PrivateImplementationDetails>`. The field name IS the hex representation of the key bytes.

```python
# Search for ldtoken (0xD0) referencing field tokens
for m in md.MethodDef:
    il_code = get_il_code(pe, m)
    if not il_code:
        continue
    for i in range(len(il_code) - 4):
        if il_code[i] == 0xD0:  # ldtoken
            token = struct.unpack('<I', il_code[i+1:i+5])[0]
            table = (token >> 24) & 0xFF
            row = token & 0x00FFFFFF
            if table == 0x04:  # FieldDef
                fields = list(md.Field)
                if row <= len(fields):
                    f_name = fields[row - 1].Name
                    # Check if it's a hex string (key material)
                    if len(f_name) in [32, 64] and all(c in '0123456789abcdefABCDEF' for c in f_name):
                        key_bytes = bytes.fromhex(f_name)
                        print(f"KEY in {m.Name}: {f_name} ({len(key_bytes)} bytes)")
```

### Detecting Zero IV

Look for `get_iv` methods that return zeroed arrays:

```python
# IL: 1f108d350100012a
# ldc.i4.s 16 -> newarr byte[16] -> ret = ZERO IV
il = get_il_code(pe, method)
if il == bytes.fromhex('1f108d350100012a'):
    print("ZERO IV detected!")
```

## Common Pitfalls

1. **US heap offset vs index**: The `ldstr` token uses **byte offset** into the US heap, not a sequential index. Parse the US heap with offset tracking, not index counting.

2. **XALZ compressed_size field**: In XABA blobs, the XALZ header's second field is an **index into the manifest**, not a compressed size. The compressed data runs until the next XALZ marker.

3. **pyxamstore failure**: The `pyxamstore` library often fails on real-world XABA blobs. Always have the manual LZ4 extraction script as fallback.

4. **Linker merging**: Don't assume the DLL named after the app contains the app logic. Check all DLLs for app-specific TypeDefs.

5. **dnfile API changes**: `dnfile` doesn't have `get_strings()` on the US heap. Use manual offset-based parsing.

## References

- [Xamarin Assembly Store Format](https://thecobraden.com/posts/unpacking_xamarin_assembly_stores/)
- [dnfile on PyPI](https://pypi.org/project/dnfile/)
- [LZ4 Block Format](https://github.com/lz4/lz4/blob/dev/doc/lz4_Block_format.md)
