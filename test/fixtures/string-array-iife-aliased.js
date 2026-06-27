// Regression fixture for the IIFE-nested, simple-subtract, aliased variant
// (PropellerAds/Adsterra sfp.js-style). The previous detector missed this
// because:
//   1. Decoder/array/rotator live inside an outer (function(){...})() — not
//      at program-body level.
//   2. The decoder uses the simple-subtract shape (no self-rewrite).
//   3. The rotator is part of a SequenceExpression, not a standalone stmt.
//   4. Calls go through per-function aliases (`var X = decoder`), never
//      through the decoder's own name.
//
// Plaintext for verification:
//   _0xdec(0x0) = "hello"
//   _0xdec(0x1) = "world"
//   _0xdec(0x2) = "foo"
//   _0xdec(0x3) = "bar"
//   _0xdec(0x4) = "baz"
//   _0xdec(0x5) = "qux"
//   _0xdec(0x6) = "quux"
//
// (Rotator uses target=1; on iter 1 the decoy parseInts evaluate to z===1, so
// the loop breaks immediately and the array is never shifted. The leading
// digits of each decoy are the `parseInt` value; trailing letters are noise
// that `parseInt` discards — same trick the real obfuscator uses.)
(function () {
  function _0xdec(o, k) {
    o = o - 0x0;
    var n = _0xarr();
    var z = n[o];
    return z;
  }
  (function (o, k) {
    var alias = _0xdec, n = o();
    while (!![]) {
      try {
        var z = parseInt("1a") / 1
              + parseInt("0b") / 2 * (parseInt("0c") / 3)
              + -parseInt("0d") / 4
              + -parseInt("0e") / 5 * (-parseInt("0f") / 6);
        if (z === k) break;
        else n.push(n.shift());
      } catch (e) {
        n.push(n.shift());
      }
    }
  }(_0xarr, 1), !function () {
    // Some other IIFE the obfuscator chains via the SequenceExpression — its
    // body is what would normally hold the rest of the user code.
    var Q = _0xdec;
    function greet() {
      var Q2 = _0xdec;
      console.log(Q(0x0) + ' ' + Q2(0x1));
      console.log(Q(0x2), Q2(0x3), Q(0x4), Q2(0x5), Q(0x6));
    }
    greet();
  }());
  function _0xarr() {
    var fL = ['hello', 'world', 'foo', 'bar', 'baz', 'qux', 'quux'];
    _0xarr = function () { return fL; };
    return _0xarr();
  }
})();
