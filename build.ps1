# MSVCとNinjaでiss-winを構成し、ビルドする。
#   ./build.ps1                 # Releaseビルド
#   ./build.ps1 -Config Debug
#   ./build.ps1 -Test           # ビルドしてから単体テストを実行
param(
    [ValidateSet("Release", "Debug", "RelWithDebInfo")]
    [string]$Config = "Release",
    [switch]$Test
)
$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$build = Join-Path $root "build\$Config"

# MSVCのx64環境はシェルごとに1回だけ読み込む。
if (-not (Get-Command cl.exe -ErrorAction SilentlyContinue)) {
    $installer = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer"
    $vswhere = Join-Path $installer "vswhere.exe"
    # VsDevCmd自身がvswhere.exeを名前で呼び出す。
    $env:PATH = "$installer;$env:PATH"
    $vs = & $vswhere -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
    if (-not $vs) { throw "MSVC (VC.Tools.x86.x64) not found" }
    Import-Module (Join-Path $vs "Common7\Tools\Microsoft.VisualStudio.DevShell.dll")
    Enter-VsDevShell -VsInstallPath $vs -SkipAutomaticLocation -DevCmdArguments "-arch=x64 -host_arch=x64" | Out-Null
}

# PATH上にあるほかのCMake/Ninjaより、Visual Studio同梱のものを優先する
# （MinGWのcmakeだとジェネレーターの既定値を取り違えるため）。
$vsCmake = Get-ChildItem "$env:VSINSTALLDIR\Common7\IDE\CommonExtensions\Microsoft\CMake" -Recurse -Filter cmake.exe -ErrorAction SilentlyContinue | Select-Object -First 1
$cmake = if ($vsCmake) { $vsCmake.FullName } else { "cmake" }
$vsNinja = Get-ChildItem "$env:VSINSTALLDIR\Common7\IDE\CommonExtensions\Microsoft\CMake" -Recurse -Filter ninja.exe -ErrorAction SilentlyContinue | Select-Object -First 1
[string[]]$cmakeArgs = @("-S", $root, "-B", $build, "-G", "Ninja", "-DCMAKE_BUILD_TYPE=$Config", "-DCMAKE_CXX_COMPILER=cl")
if ($vsNinja) { $cmakeArgs += "-DCMAKE_MAKE_PROGRAM=$($vsNinja.FullName)" }

& $cmake @cmakeArgs
if ($LASTEXITCODE) { exit $LASTEXITCODE }
& $cmake --build $build
if ($LASTEXITCODE) { exit $LASTEXITCODE }

if ($Test) {
    & (Join-Path $build "bin\iss-tests.exe")
    if ($LASTEXITCODE) { exit $LASTEXITCODE }
}
