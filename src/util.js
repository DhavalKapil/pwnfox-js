// Converts an integer value in hex string, pads to 'pad' bytes
function hexString(value, pad) {
  pad = typeof pad !== 'undefined' ? pad : 8;
  var str = value.toString(16);
  var padded_str = str;
  for (i = 0;i<(2*pad - str.length);i++) {
    padded_str = "0" + str;
  }
  return padded_str;
}

function readUpto(a_read, addr, num) {
  // Currently assumes a_read gives 4 bytes
  var bytes = [];
  var read_addr = Int64.copy(addr);
  while (num > 0) {
    bytes = bytes.concat(a_read(read_addr));
    num -= 4;
    read_addr.addOp(4);
  }
  bytes.slice(num);
  return bytes;
}

function writeUpto(a_write, addr, bytes) {
  var written = 0;
  var write_addr = Int64.copy(addr);
  while (written < bytes.length) {
    a_write(write_addr, bytes.slice(written, written + 4));
    written += 4;
    write_addr.addOp(4);
  }
}

function writeInt64(a_write, addr, value) {
  var bytes = [];
  for (i = 0;i<8;i++) {
    bytes[i] = value.memory[i];
  }
  writeUpto(a_write, addr, bytes);
}

// Reads a string (till a null byte)
function readStr(a_read, addr) {
  var str = "";
  var read_addr = Int64.copy(addr);
  while (true) {
    var bytes = a_read(read_addr);
    for (i = 0;i<bytes.length;i++) {
      if (bytes[i] == 0) {
        return str;
      }
      str += String.fromCharCode(bytes[i]);
    }
    read_addr.addOp(4);
  }
}
