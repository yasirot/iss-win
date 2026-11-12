# デコーダーのテスト用に、Annex-B形式の短いテストクリップと、フレームごとの
# 参照MD5を作る。third_partyのFFmpegを使う（ハードウェアエンコーダーは
# HEVCがNVENC、H.264がOpenH264）。tests/data/*.{h265,h264,md5}に書き出す。
#
#   ./tools/make_test_clips.ps1
$ErrorActionPreference = "Stop"
$root = Split-Path $PSScriptRoot -Parent
$ff = Join-Path $root "third_party\ffmpeg\bin\ffmpeg.exe"
$out = Join-Path $root "tests\data"
New-Item -ItemType Directory -Force $out | Out-Null

# 30フレーム、640x360、Bフレームなし（Appleのストリームにもない）、IDRは10フレームごと。
$src = @("-f", "lavfi", "-i", "testsrc2=size=640x360:rate=30", "-frames:v", "30")

$clips = @(
    @{ name = "hevc444"; ext = "h265"; args = @("-pix_fmt", "yuv444p", "-c:v", "hevc_nvenc", "-profile:v", "rext", "-bf", "0", "-g", "10") },
    @{ name = "hevc420"; ext = "h265"; args = @("-pix_fmt", "yuv420p", "-c:v", "hevc_nvenc", "-profile:v", "main", "-bf", "0", "-g", "10") },
    @{ name = "h264";    ext = "h264"; args = @("-pix_fmt", "yuv420p", "-c:v", "libopenh264", "-g", "10") }
)

foreach ($c in $clips) {
    $file = Join-Path $out "$($c.name).$($c.ext)"
    & $ff -hide_banner -loglevel error -y @src @($c.args) -f $(if ($c.ext -eq "h265") { "hevc" } else { "h264" }) $file
    if ($LASTEXITCODE) { throw "encode $($c.name) failed" }
    # 参照値はソフトウェアでデコードし、生のプレーンのMD5をフレームごとに取る。
    & $ff -hide_banner -loglevel error -y -i $file -f framemd5 (Join-Path $out "$($c.name).md5")
    if ($LASTEXITCODE) { throw "framemd5 $($c.name) failed" }
    "{0,-10} {1,8} bytes" -f $c.name, (Get-Item $file).Length
}
