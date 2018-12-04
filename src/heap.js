var KB = 0x400;
var MB = 0x100000;
var GB = 0x40000000;

function run_garbage_collector() {
  var maxMallocBytes = 128 * MB;
  for (var i = 0; i < 3; i++) {
    var x = new ArrayBuffer(maxMallocBytes);
  }
}
