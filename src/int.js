/*
 * Much of this code is shamelessly copied from
 * https://github.com/saelo/feuerfuchs/blob/master/exploit/pwn.js
 */

function Int64(lower, upper) {
  // The underlying memory
  this.memory = new Uint8Array(8);

  for (var i = 0;i<4;i++) {
    this.memory[i] = lower % 0x100;
    this.memory[i+4] = upper % 0x100;
    lower /= 0x100;
    upper /= 0x100;
  }
}

// Decorator for Int64 instance operations. Takes care
// of converting arguments to Int64 instances if required.
function operation(f, nargs ) {
  return function() {
    if (arguments.length != nargs)
      throw Error("Not enough arguments for function " + f.name);
    for (var i = 0; i < arguments.length; i++)
      if (!(arguments[i] instanceof Int64))
        arguments[i] = new Int64(  // jshint ignore:line
          arguments[i] % 0x100000000,
          Math.floor(arguments[i] / 0x100000000)
        );
    return f.apply(this, arguments);
  };
}

Int64.prototype.bytes = function() {
  return Array.from(this.memory);
};

Int64.prototype.toString = function() {
  var str = "0x";
  for (var i = 7;i>=0;i--) {
    str += hexString(this.memory[i], 1);
  }
  return str;
};

// Returns the lowest 4 bytes
Int64.prototype.lower = function() {
  var value = 0;
  for (var i = 3;i>=0;i--) {
    value = value*0x100 + this.memory[i];
  }
  return value;
};

// Returns the highest 4 bytes
Int64.prototype.upper = function() {
  var value = 0;
  for (var i = 7;i>=4;i--) {
    value = value*0x100 + this.memory[i];
  }
  return value;
};

// Operations, changes current object
Int64.prototype.addOp = operation(function add(num) {
  var carry = 0;
  for (var i = 0;i<8;i++) {
    var val = this.memory[i] + num.memory[i] + carry;
    carry = val > 0xff | 0;
    this.memory[i] = val;
  }
  return this;
}, 1);

Int64.prototype.subOp = operation(function sub(num) {
  var carry = 0;
  for (var i = 0;i<8;i++) {
    var val = this.memory[i] - num.memory[i] - carry;
    carry = val < 0 | 0;
    this.memory[i] = val;
  }
  return this;
}, 1);

Int64.prototype.lshift1Op = operation(function lshift1() {
  var highBit = 0;
  for (var i = 0; i < 8; i++) {
    var cur = this.memory[i];
    this.memory[i] = (cur << 1) | highBit;
    highBit = (cur & 0x80) >> 7;
  }
  return this;
}, 0);

Int64.prototype.rshift1Op = operation(function rshift1(a) {
  var lowBit = 0;
  for (var i = 7; i >= 0; i--) {
    var cur = this.memory[i];
    this.memory[i] = (cur >> 1) | lowBit;
    lowBit = (cur & 0x1) << 7;
  }
  return this;
}, 0);

Int64.prototype.andOp = operation(function and(num) {
  for (var i = 0; i < 8; i++) {
    this.memory[i] &= num.memory[i];
  }
  return this;
}, 1);

Int64.prototype.orOp = operation(function or(num) {
  for (var i = 0; i < 8; i++) {
    this.memory[i] |= num.memory[i];
  }
  return this;
}, 1);

Int64.prototype.xorOp = operation(function xor(num) {
  for (var i = 0; i < 8; i++) {
    this.memory[i] ^= num.memory[i];
  }
  return this;
}, 1);

// Generates a copy of the object
Int64.copy = function(obj) {
  return new Int64(obj.lower(), obj.upper());
};

Int64.add = function(obj1, obj2) {
  return Int64.copy(obj1).addOp(obj2);
};

Int64.sub = function(obj1, obj2) {
  return Int64.copy(obj1).subOp(obj2);
};

Int64.lshift1 = function(obj) {
  return Int64.copy(obj).lshift1Op();
};

Int64.rshift1 = function(obj) {
  return Int64.copy(obj).rshift1Op();
};

Int64.and = function(obj1, obj2) {
  return Int64.copy(obj1).andOp(obj2);
};

Int64.or = function(obj1, obj2) {
  return Int64.copy(obj1).orOp(obj2);
};

Int64.xor = function(obj1, obj2) {
  return Int64.copy(obj1).xorOp(obj2);
};

