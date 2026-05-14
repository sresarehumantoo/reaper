function _0xarr() {
  const a = ['hello', 'world', 'foo', 'bar', 'baz', 'qux', 'quux'];
  _0xarr = function () { return a; };
  return _0xarr();
}
function _0xdec(idx, _ignored) {
  const arr = _0xarr();
  return _0xdec = function (i, _) { i = i - 0x0; return arr[i]; }, _0xdec(idx, _ignored);
}
(function (arr, target) {
  while (!![]) {
    try {
      if (target === 1) break;
      else arr['push'](arr['shift']());
    } catch (e) {
      arr['push'](arr['shift']());
    }
  }
}(_0xarr, 1));

function greet() {
  console.log(_0xdec(0x0, 'k') + ' ' + _0xdec(0x1, 'k'));
}
greet();
