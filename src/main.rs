use anyhow::Context;
use byteorder::ByteOrder;
use byteorder::LittleEndian;
use goblin::elf::Elf;
use goblin::elf64::program_header::PT_LOAD;
use memmap2::Mmap;
use std::collections::HashMap;
use std::fs::File;

use capstone::arch::arm64::Arm64Insn;
use capstone::arch::arm64::Arm64OperandType;
use capstone::prelude::*;
use goblin::elf::program_header::ProgramHeader;
use goblin::elf::sym::STT_FUNC;
use serde::Serialize;

const UPACKAGE_SCRIPT_COMMONSOURCE: u64 = 0x09ac3d8c;
//_Z39Z_Construct_UScriptStruct_FBaseProtocolv
const FBASE_PROTOCOL: u64 = 0x09bce1dc;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub enum FieldType {
    // scalars
    U8,
    I32,
    I64,
    F32,
    StringUtf16,
    Bool,

    // containers / references
    Array(Box<FieldType>), // Array(<element-type>)
    Struct(String),        // name of referenced struct
    Enum {
        name: String,
        repr: Option<Box<FieldType>>,
    }, // name of referenced enum

    // fall-backs
    Unresolved,   // “I don’t know yet”
    Unknown(u32), // future-proof numeric tag
}

fn to_field_type(code: u32, subtype: Option<String>) -> FieldType {
    use FieldType::*;
    match code {
        0 => U8,
        3 => I32,
        4 => I64,
        10 => F32,
        21 => StringUtf16,
        22 => Array(Box::new(Unresolved)), // will be fixed up later
        25 => Struct(subtype.unwrap()),
        30 => FieldType::Enum {
            name: subtype.unwrap(),
            repr: None,
        },
        44 => Bool,
        other => Unknown(other),
    }
}

/// Parsed Enum  / Class / Packet results
#[derive(Debug, Serialize)]
struct EnumDef {
    name: String,               // “EErrorCode”
    repr: String,               // “u8”, “i32”, “i64”
    fields: Vec<(String, u64)>, // [{ "OK", 0 }, { "Fail", 1 }, …]
}

//#[derive(Debug, Serialize)]
//struct ClassInfo {
//    name: String,
//    mem_size: u64,
//    flags: u64,
//    fields: Vec<Field>,
//}

#[derive(Debug, Serialize)]
struct PacketInfo {
    name: String,
    mem_size: u64,
    flags: u64,
    fields: Vec<Field>,
}

#[derive(Debug, Clone, Serialize)]
struct Field {
    name: String,
    f_type: FieldType,
    offset: u32,            // “this” field’s byte offset inside the parent struct
    ty_ptr: Option<String>, // resolved via funcdesc for 25/30; else 0
    unk1: u64,
    unk2: u32,
    unk3: u32,
    unk4: u32,
    unk5: u32,
}

struct Mem<'a> {
    data: &'a [u8],
    phs: Vec<ProgramHeader>,

    addr2name: HashMap<u64, String>,
    name2addr: HashMap<String, u64>,
}

impl<'a> Mem<'a> {
    fn new(data: &'a [u8]) -> Result<(Self, Elf<'a>), anyhow::Error> {
        let elf = Elf::parse(data)?;
        let (addr2name, name2addr) = build_symbol_maps(&elf);
        Ok((
            Self {
                data,
                phs: elf.program_headers.clone(), // keep a local copy
                addr2name,
                name2addr,
            },
            elf,
        ))
    }

    /// Map an *in-image* virtual address to a file offset.
    /// Returns `None` when the address falls outside all PT_LOAD segments.
    fn vaddr_to_off(&self, vaddr: u64) -> Option<usize> {
        self.phs.iter().find_map(|ph| {
            if ph.p_type != PT_LOAD {
                return None;
            }
            let seg_start = ph.p_vaddr;
            let seg_end = ph.p_vaddr + ph.p_filesz.max(ph.p_memsz);
            if vaddr >= seg_start && vaddr < seg_end {
                Some((ph.p_offset + (vaddr - seg_start)) as usize)
            } else {
                None
            }
        })
    }

    fn read_bytes(&self, vaddr: u64, len: usize) -> Result<&'a [u8], anyhow::Error> {
        let off = self
            .vaddr_to_off(vaddr)
            .ok_or_else(|| anyhow::anyhow!("vaddr {:#x} outside PT_LOAD", vaddr))?;
        self.data
            .get(off..off + len)
            .with_context(|| format!("slice out of range (vaddr {:#x})", vaddr))
    }

    fn read_u64(&self, vaddr: u64) -> Result<u64, anyhow::Error> {
        Ok(LittleEndian::read_u64(self.read_bytes(vaddr, 8)?))
    }

    fn get_ascii_string(&self, vaddr: u64) -> anyhow::Result<String> {
        let off = self
            .vaddr_to_off(vaddr)
            .ok_or_else(|| anyhow::anyhow!("string addr {:#x} outside PT_LOAD", vaddr))?;

        let slice = &self.data[off..];
        let nul = slice
            .iter()
            .position(|&b| b == 0)
            .ok_or_else(|| anyhow::anyhow!("unterminated ASCII @ {:#x}", vaddr))?;

        Ok(std::str::from_utf8(&slice[..nul])?.to_owned())
    }
}

fn build_symbol_maps(elf: &Elf) -> (HashMap<u64, String>, HashMap<String, u64>) {
    // pick the right tables
    let (table, strtab) = if !elf.syms.is_empty() {
        (&elf.syms, &elf.strtab)
    } else {
        (&elf.dynsyms, &elf.dynstrtab)
    };

    let mut addr2name = HashMap::<u64, String>::new();
    let mut name2addr = HashMap::<String, u64>::new();

    for sym in table {
        // skip undefined or zero-sized symbols
        if sym.st_value == 0 || sym.st_size == 0 {
            continue;
        }

        // get the string-table entry; skip empty names
        let Some(name) = strtab.get_at(sym.st_name).filter(|n| !n.is_empty()) else {
            continue;
        };

        // own the string (Strtab gives &str)
        let name_owned = name.to_owned();
        let addr = sym.st_value;

        // insert both directions; keep the first if duplicates appear
        addr2name.entry(addr).or_insert_with(|| name_owned.clone());
        name2addr.entry(name_owned).or_insert(addr);
    }

    (addr2name, name2addr)
}

fn read_packet(mem: &Mem, entry: u64) -> Result<(u64, PacketInfo), anyhow::Error> {
    let rec = mem.read_bytes(entry, 72)?;
    let s_name = mem.get_ascii_string(LittleEndian::read_u64(&rec[24..32]))?;
    let u_size = LittleEndian::read_u64(&rec[32..40]);
    let u_flags = LittleEndian::read_u64(&rec[40..48]);
    let p_fields = LittleEndian::read_u64(&rec[48..56]);
    let field_cnt = LittleEndian::read_u32(&rec[56..60]) as usize;

    let mut fields = read_fields(mem, p_fields, field_cnt)?;
    fields.sort_by_key(|f| f.offset);

    //println!(
    //    "===============\n{:?} {} {} fields_ptr: {} cnt: {}",
    //    s_name, u_size, u_flags, p_fields, field_cnt
    //);
    //for field in &fields {
    //    println!("{:?}", field);
    //}

    Ok((
        entry,
        PacketInfo {
            name: s_name,
            mem_size: u_size,
            flags: u_flags,
            fields,
        },
    ))
}

fn read_enum(mem: &Mem, entry: u64) -> Option<EnumDef> {
    // ---- quick pattern check -------------------------------------------
    let hdr = mem.read_bytes(entry, 56).ok()?; // 7×u64 = 56 bytes
    if LittleEndian::read_u64(&hdr[8..16]) != 0 {
        return None;
    } // 2nd = 0

    let name_ptr = LittleEndian::read_u64(&hdr[16..24]);
    let name_dup = LittleEndian::read_u64(&hdr[24..32]);
    if name_ptr != name_dup {
        return None;
    } // 4th==5th

    let fields_ptr = LittleEndian::read_u64(&hdr[32..40]);
    let field_cnt = LittleEndian::read_u32(&hdr[40..44]) as usize;
    if LittleEndian::read_u64(&hdr[44..52]) != 0x45 {
        return None;
    } // sentinel 69

    // ---- read the string & field tuples --------------------------------
    let name = mem.get_ascii_string(name_ptr).ok()?;

    let blob = mem.read_bytes(fields_ptr, field_cnt * 16).ok()?;
    let mut fields = Vec::with_capacity(field_cnt);

    for i in 0..field_cnt {
        let p = i * 16;
        let fname_ptr = LittleEndian::read_u64(&blob[p..p + 8]);
        let value = LittleEndian::read_u64(&blob[p + 8..p + 16]);

        // -------- read & clean the constant name ---------------------------
        let mut fname = mem.get_ascii_string(fname_ptr).ok()?;
        // drop the `EnumName::` prefix if present
        if let Some(stripped) = fname.strip_prefix(&format!("{}::", name)) {
            fname = stripped.to_owned();
        }

        fields.push((fname, value));
    }

    // ---- crude repr inference from max value ---------------------------
    let maxv = fields.iter().map(|(_, v)| *v).max().unwrap_or(0);
    let repr = if maxv <= u8::MAX as u64 {
        "u8"
    } else if maxv <= i32::MAX as u64 {
        "i32"
    } else {
        "i64"
    }
    .to_owned();

    Some(EnumDef { name, repr, fields })
}

fn read_fields(mem: &Mem, arr_ptr: u64, count: usize) -> anyhow::Result<Vec<Field>> {
    if count == 0 {
        return Ok(Vec::new());
    }

    let ptrs = mem.read_bytes(arr_ptr, count * 8)?;

    let mut out_rev = Vec::with_capacity(count); // we’ll reverse at the end
    let mut i: isize = count as isize - 1; // start at the tail

    while i >= 0 {
        // -------- read current record ------------------------------------
        let field_addr = LittleEndian::read_u64(&ptrs[(i as usize) * 8..][..8]);
        let mut field = read_field(mem, field_addr)?;

        // ===== CASE 1  •  UnderlyingType (must belong to an enum) ========
        if field.name == "UnderlyingType" {
            anyhow::ensure!(i > 0, "dangling UnderlyingType at index {}", i);

            // peek the *preceding* record – must be an enum header
            let prev_addr = LittleEndian::read_u64(&ptrs[(i as usize - 1) * 8..][..8]);
            let mut enum_field = read_field(mem, prev_addr)?;

            match &mut enum_field.f_type {
                FieldType::Enum { repr, .. } => {
                    *repr = Some(Box::new(field.f_type.clone()));
                }
                _ => anyhow::bail!(
                    "UnderlyingType followed something that is not an enum @ index {}",
                    i - 1
                ),
            }

            out_rev.push(enum_field); // push *only* the decorated enum
            i -= 2; // consumed the enum + helper
            continue;
        }

        // ===== CASE 2  •  Element of an array (prev is the header) =======
        if i > 0 {
            let prev_addr = LittleEndian::read_u64(&ptrs[(i as usize - 1) * 8..][..8]);
            let mut prev_field = read_field(mem, prev_addr)?;

            if matches!(prev_field.f_type, FieldType::Array(_)) {
                // merge: header becomes Array(<element-field-type>)
                prev_field.f_type = FieldType::Array(Box::new(field.f_type.clone()));
                out_rev.push(prev_field); // push merged entry
                i -= 2; // consumed header + element
                continue;
            }
        }

        // ===== CASE 3  •  Ordinary field – just keep it ===================
        out_rev.push(field);
        i -= 1;
    }

    // we built it backwards – flip to forward order…
    out_rev.reverse();
    // …and keep the “sorted by offset” guarantee
    out_rev.sort_by_key(|f| f.offset);
    Ok(out_rev)
}

/// Try to decode the 32-bit word at `addr` as a single AArch64 store and
/// return its immediate displacement (e.g. 0x24 in `strb w8,[x0,#0x24]`).
fn arm64_store_imm(mem: &Mem, addr: u64) -> anyhow::Result<u32> {
    let bytes = mem.read_bytes(addr, 4)?; // one instruction
    let cs = Capstone::new()
        .arm64()
        .mode(arch::arm64::ArchMode::Arm)
        .detail(true)
        .build()?;

    let insns = cs.disasm_all(bytes, addr)?;
    let insn = insns
        .iter()
        .next()
        .ok_or_else(|| anyhow::anyhow!("no insn"))?;

    // Accept STR / STRB / STRH of any width
    match insn.id().0 {
        id if id == Arm64Insn::ARM64_INS_STR as u32
            || id == Arm64Insn::ARM64_INS_STRB as u32
            || id == Arm64Insn::ARM64_INS_STRH as u32 =>
        {
            let detail = cs.insn_detail(&insn)?;
            let detail = detail.arch_detail();
            let arch = detail
                .arm64()
                .ok_or_else(|| anyhow::anyhow!("no arm64 detail"))?;

            for op in arch.operands() {
                if let Arm64OperandType::Mem(ref m) = op.op_type {
                    // The displacement is the immediate we need
                    return Ok(m.disp() as u32);
                }
            }
            Err(anyhow::anyhow!("store has no mem operand"))
        }
        _ => Err(anyhow::anyhow!("not a store insn at {:#x}", addr)),
    }
}

fn read_field(mem: &Mem, field_addr: u64) -> anyhow::Result<Field> {
    // field record is always 0x38 bytes
    let rec = mem.read_bytes(field_addr, 0x38)?;

    // byte-slice decoding (offsets match your pattern)
    let s_name = LittleEndian::read_u64(&rec[0..8]);
    let unk1 = LittleEndian::read_u64(&rec[8..16]);
    let unk2 = LittleEndian::read_u32(&rec[16..20]);
    let unk3 = LittleEndian::read_u32(&rec[20..24]);
    let f_type = LittleEndian::read_u32(&rec[24..28]);
    let unk4 = LittleEndian::read_u32(&rec[28..32]);
    let unk5 = LittleEndian::read_u32(&rec[32..36]);
    let raw_offset = LittleEndian::read_u32(&rec[36..40]);
    let func_desc = LittleEndian::read_u64(&rec[40..48]);
    let func_desc1 = LittleEndian::read_u64(&rec[48..56]);

    let name = mem.get_ascii_string(s_name)?;

    let (offset, ty_ptr) = match f_type {
        25 | 30 => {
            // type = MetaData.funcdesc(...)
            // Here we just read the pointee; swap in a real parser later.

            let sub_name = mem.addr2name.get(&func_desc);

            (raw_offset, sub_name)
        }
        44 => {
            // offset = MetaData.funcdesc_44(...)
            let off = arm64_store_imm(mem, func_desc1 + 4).unwrap_or(0);
            (off, None)
        }
        _ => (raw_offset, None),
    };

    let f_type = to_field_type(f_type, ty_ptr.cloned());

    let ty_ptr = ty_ptr.cloned();

    Ok(Field {
        name,
        f_type,
        offset,
        ty_ptr,
        unk1,
        unk2,
        unk3,
        unk4,
        unk5,
    })
}

fn collect_non_function_symbols(elf: &Elf) -> Vec<(String, u64)> {
    // Pick the right symbol + string table pair
    let (table, strtab) = if !elf.syms.is_empty() {
        (&elf.syms, &elf.strtab)
    } else {
        (&elf.dynsyms, &elf.dynstrtab)
    };

    table
        .iter()
        // skip undefined / 0-sized / functions
        .filter(|sym| sym.st_value != 0 && sym.st_size != 0 && sym.st_type() != STT_FUNC)
        // map to (name, address) if the name exists and is non-empty
        .filter_map(|sym| {
            strtab
                .get_at(sym.st_name)
                .filter(|n| !n.is_empty())
                .map(|name| (name.to_owned(), sym.st_value))
        })
        .collect()
}

fn scan_for_enums(mem: &Mem, common_source: u64) -> Vec<EnumDef> {
    use std::collections::BTreeMap; // stable, dedup

    let mut map = BTreeMap::<String, EnumDef>::new();

    for ph in &mem.phs {
        if ph.p_type != PT_LOAD {
            continue;
        }

        let seg = &mem.data[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
        let base = ph.p_vaddr;

        // walk 8-byte aligned
        let upper = seg.len().saturating_sub(40);
        for off in (0..upper).step_by(8) {
            let q0 = LittleEndian::read_u64(&seg[off..off + 8]);
            if q0 != common_source {
                continue;
            }

            let q1 = LittleEndian::read_u64(&seg[off + 8..off + 16]);
            if q1 != 0 {
                continue;
            }

            let q3 = LittleEndian::read_u64(&seg[off + 16..off + 24]);
            let q4 = LittleEndian::read_u64(&seg[off + 24..off + 32]);
            if q3 != q4 {
                continue;
            }

            let addr = base + off as u64;
            if let Some(e) = read_enum(mem, addr) {
                map.entry(e.name.clone()).or_insert(e); // dedup by name
            }
        }
    }
    map.into_values().collect()
}

fn main() -> Result<(), anyhow::Error> {
    let path = std::env::args()
        .nth(1)
        .context("provide .so path on the CLI")?;
    let file = File::open(&path)?;
    let map = unsafe { Mmap::map(&file)? };
    let (mem, elf) = Mem::new(&map)?;

    let common_source = *mem
        .name2addr
        .get("_Z41Z_Construct_UPackage__Script_CommonSourcev")
        .context("symbol CommonSource not found")?;

    let protocol_base = *mem
        .name2addr
        .get("_Z39Z_Construct_UScriptStruct_FBaseProtocolv")
        .context("symbol FBaseProtocol not found")?;

    let enums = scan_for_enums(&mem, common_source);
    //println!("enum: {:?}\n", anenum);

    println!("{} {}", common_source, protocol_base);
    let data_syms = collect_non_function_symbols(&elf);
    println!("Non-function symbols: {}", data_syms.len());

    let mut packets = Vec::<PacketInfo>::new();
    let mut structs = Vec::<PacketInfo>::new(); // optional for later

    for (_name, addr) in &data_syms {
        // ---- quick filter on q0 -------------------------------------------
        let q0 = mem.read_u64(*addr);
        if !q0.is_ok() || q0.unwrap() != common_source {
            continue;
        }

        let q1 = mem.read_u64(addr + 8)?;
        if q1 != 0 {
            // ============ PACKET ============================================
            if let Ok((_, pkt)) = read_packet(&mem, *addr) {
                packets.push(pkt);
            }
            continue;
        }

        //println!("class {}", _name);
        // ============ STRUCT (class) ====================================
        if let Ok(cls) = read_packet(&mem, *addr) {
            // implement when needed
            structs.push(cls.1);
        }
    }

    //lets search the memory for
    //
    let json = serde_json::to_string_pretty(&packets)?;
    std::fs::write("packets.json", &json)?;

    let json = serde_json::to_string_pretty(&enums)?;
    std::fs::write("enums.json", &json)?;

    //let src = generate_rust(&packets);
    //std::fs::write("packets.rs", src)?;

    let ex = generate_elixir(&packets, "Proto.Packets");
    std::fs::write("packets.ex", ex)?;

    let ex = generate_elixir(&structs, "Proto.Structs");
    std::fs::write("structs.ex", ex)?;

    Ok(())
}

use std::fmt::Write;

fn elixir_atom(src: &str) -> String {
    let mut out = String::with_capacity(src.len() + 4);
    for (i, ch) in src.chars().enumerate() {
        if ch.is_ascii_uppercase() {
            if i != 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn generate_elixir(packets: &[PacketInfo], space: &str) -> String {
    let mut buf = String::with_capacity(4096);
    buf.push_str("# Auto-generated: DO NOT EDIT\n");
    buf.push_str(&format!("defmodule {} do\n\n", space));

    for pkt in packets {
        buf.push_str(&format!("  defmodule {} do\n", pkt.name));
        buf.push_str("    @enforce_keys []\n");
        buf.push_str("    defstruct [\n");

        for f in &pkt.fields {
            writeln!(
                &mut buf,
                "      :{},  # offset 0x{:X}",
                elixir_atom(&f.name),
                f.offset
            )
            .unwrap();
        }

        buf.push_str("    ]\n  end\n\n");
    }

    buf.push_str("end\n");
    buf
}
