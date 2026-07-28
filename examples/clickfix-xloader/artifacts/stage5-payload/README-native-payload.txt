FINAL NATIVE PAYLOAD (NOT COMMITTED)

Unlike the JavaScript/PowerShell stages, the terminal Windows binary is NOT
shipped in this repository. It is a live, packed XLoader/Formbook sample and,
as delivered, is 781 MB of null-padding around ~250 KB of real code, far too
large and too dangerous to commit. Only its metadata is recorded here.

Retrieval chain (see ../stage4-powershell/dropper-iocs.txt):
  http://enter-code-cdn.info/7z                 -> 7za.exe extractor
  http://enter-code-cdn.info/<64hex>            -> payload.7z  (pw: password1234)
  payload.7z  --extract-->  xloader.exe          -> executed via Start-Process

File facts (observed 2026-07-28):
  7za.exe (extractor)
    size   : 858112 bytes
    sha256 : 26817725650583d99ca3e617a618dd75c0f71bd316b5761780b7361f5f824cad
    note   : legitimate 7-Zip standalone console build, abused as an unpacker

  payload.7z
    size   : 230658 bytes
    sha256 : 5120cc6dfbbb629310405145065fc433a7d64c48936403718903b95bc6491ab9
    method : LZMA2 + 7zAES (password-protected: password1234)

  xloader.exe  (contents of payload.7z)
    size on disk : 819450880 bytes (781.5 MB)
    real content : ~250 KB  (100.0% of the remaining 781 MB tail is 0x00 padding)
    sha256       : 8826bebdbb2db70a451199e60189a179737ac5c4c383f7cc763ff73395e3de5a
    PE           : PE32+ / x86-64 / GUI / 7 sections
    SizeOfImage  : 278528
    compiled     : 2026-07-10T16:23:19Z
    imports      : KERNEL32, USER32, GDI32, ole32, OLEAUT32 (minimal; packed)
    tells        : IsDebuggerPresent, VirtualProtect, LoadLibraryExW,
                   GetProcAddress, CreateThread  (in-memory unpack + anti-debug)
    family       : XLoader / Formbook (infostealer), inferred from filename,
                   packing, and delivery; C2 config is encrypted in the stub.

Why the file bloat matters: the archive is 230 KB on the wire but inflates to
819 MB on disk. Many AV/EDR/sandbox pipelines skip files over a size cap
(commonly 100-500 MB) and will not scan or auto-submit the extracted binary.
The password-protected archive blocks inline content inspection in transit.
