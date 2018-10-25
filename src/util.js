// Converts an integer value in hex string, pads to 'pad' bytes
function hexString(value, pad) {
  pad = typeof pad !== 'undefined' ? pad : 8;
  return value.toString(16).padStart(2*pad, "0");
}

function readUpto(a_read, addr, num) {
  // Currently assumes a_read gives 4 bytes
  var bytes = [];
  while (num > 0) {
    bytes.concat(a_read(addr));
    num -= 4;
  }
  bytes.slice(num);
  return bytes;
}
