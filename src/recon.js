function get_system_offset(fclose_offset) {
  for (var i = 0;i<libc_db.length;i++) {
    // if (libc_db[i].fclose == fclose_offset &&
    //     libc_db[i].toupper == toupper_offset) {
    //   return libc_db[i].system;
    // }
    if (libc_db[i].fclose == fclose_offset) {
      return libc_db[i].system;
    }
  }
}
