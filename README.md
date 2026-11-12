# iss-win

[iShareScreen](https://github.com/Chapoly1305/iShareScreen)（Python）をWindowsネイティブに移植したビューアです。macOSの画面共有（Screen Sharing）に接続して画面を表示し、キーボードとマウスを送ります。C++20、Win32、Direct3D 11、CNG（BCrypt）で書いています。

WindowsからMacに接続するために、Claude CodeでのVibeコーディングにて作成されています。

## できること

| 機能 | 内容 |
|---|---|
| 高パフォーマンス | 映像をUDPで受け取ります。H.264は3840x2160まで、HEVCは7680x4320まで（5Kの全画面も可）。AppleシリコンでmacOS 14以降のMacで使えます |
| 標準モード | 画面をTCPの制御チャネルで受け取ります。高パフォーマンスが使えないMac向けです |
| 自動解像度 | ウィンドウの大きさに合わせてMacの仮想ディスプレイを作り、サイズ変更にも追従します |
| 2画面 | Macに仮想ディスプレイを2枚作り、Windowsの別々のウィンドウに出します |
| 全画面 | Ctrl+Alt+Enterで切り替えます |
| キーボード | WindowsキーをMacのCommandとして送ります |
| パケットの欠け | 欠けた帯だけを止め、すぐMacに更新を頼みます。HEVCでは多くの場合0.1秒以内に戻ります |

音声、クリップボード、Mac本体の複数モニタには、まだ対応していません。

## ビルド

Visual Studio Build Tools（MSVC x64）と、FFmpeg 8.1のLGPL shared版が要ります。FFmpegはリポジトリに含めていないので、[BtbN/FFmpeg-Builds](https://github.com/BtbN/FFmpeg-Builds/releases)から`win64-lgpl-shared`の8.1系のzipを取り、`third_party/ffmpeg/`の直下に`bin/`、`include/`、`lib/`が来るように展開してください。

```powershell
./build.ps1          # Releaseビルド
./build.ps1 -Test    # ビルドしてユニットテストを実行
```

成果物は`build/Release/bin/`に出ます。FFmpegのDLLもそこへコピーされます。

## 使い方

`iss-win.exe`を起動すると接続ダイアログが開きます。ホスト、ユーザー名、パスワードを入れて「接続」を押してください。つながった接続先は「接続先」の一覧に残り、次からはそこから選べます。設定はレジストリ（`HKCU\Software\iShareScreen\iss-win`）に、「パスワードを保存する」を付けたときのパスワードはWindowsの資格情報マネージャーに保存します。

初回にWindowsファイアウォールの許可ダイアログが出たら、プライベートネットワークを許可してください。映像はUDP 5900〜5902で届きます。

ダイアログで選べる項目は次のとおりです。

| 項目 | 内容 |
|---|---|
| モード | 高パフォーマンスか標準。標準では画質（白黒、16階調グレー、約3万色、高画質、適応）も選べ、接続中もメニューの「画質」で切り替えられます |
| 映像 | H.264、HEVC 4:2:0、HEVC 4:4:4（高パフォーマンスのときだけ） |
| 解像度 | 既定は「自動」です。固定の大きさも選べます |
| カーテン | Macの画面を隠すかどうか |
| 2画面 | Macの仮想ディスプレイを2枚にするかどうか（カーテンありのときだけ） |

### HEVCとGPU

HEVCの4:4:4をデコードできるGPUは限られます。AMDのGPUだけのPCでは、HEVC 4:2:0かH.264を選んでください。

| 映像 | デコード | 使えるGPU |
|---|---|---|
| HEVC 4:2:0 | D3D11VA（描画と同じGPU） | HEVC 4:2:0をデコードできるGPU（AMD、NVIDIA、Intel） |
| HEVC 4:4:4 | Intel Quick Sync | Intelの内蔵GPU |

### キーボード

WindowsキーはMacのCommandになり、Win+CはCmd+C、Win+SpaceはCmd+Spaceとして届きます。AltはOption、CtrlはControlです。Win+L、Ctrl+Alt+Del、Alt+TabはWindows側で効きます。WindowsキーをWindowsに任せたいときは`--no-keyboard-grab`を付けます。

### 2画面と全画面

2画面では、Macのウィンドウをボタンを押したままもう一方のウィンドウへ動かすと、ディスプレイの間でドラッグできます。Ctrl+Alt+Enterか、タイトルバーを右クリックして出るメニューの「全画面表示」で全画面にすると、2画面ではそれぞれのウィンドウが自分のモニタで全画面になります。

### コマンドライン

| オプション | 内容 |
|---|---|
| `--connect` | ダイアログを出さず、前回の設定と保存したパスワードでつなぐ |
| `--host`、`--port`、`--user` | 接続先 |
| `--password-stdin` | パスワードを標準入力の1行目から読む |
| `--fullscreen` | 全画面で起動する |
| `--displays 1\|2` | 画面の数 |
| `--advertise WxH@S` | Macのディスプレイの大きさを固定する（例`1920x1080@2`） |
| `--h264`、`--hevc420`、`--hevc` | 映像の形式（ダイアログの選択より優先）。HEVCには大きさも付けられる（例`--hevc420 2560x1440@2`） |
| `--standard`、`--quality 画質` | 標準モードと、その画質（`adaptive`、`bw`、`gray`、`thousands`、`millions`） |
| `--gpu 名前か番号`、`--list-gpus` | 描画とデコードに使うGPU、GPUの一覧 |
| `--ipv4`、`--ipv6` | 使うアドレスファミリー |
| `--alt-session` | 別のユーザーがログイン中でも、自分のユーザーで別セッションを開く |
| `--no-curtain` | Macの画面を隠さない |
| `--view-only` | このPCのキーボードとマウスをMacに送らない |
| `--log` | ログをカレントディレクトリの`logs\iss-win.log`に書く |

動作確認と計測のためのオプションもあります。`--perf`は5秒ごとにフレームレートと遅延をログに出し、`--smoke N`はN秒で終了し、`--play`はローカルの動画ファイル（.h264、.h265）を再生します。ほかのオプションは`src/app/main.cpp`の先頭にまとめてあります。

## 接続確認（iss-check.exe）

Macに届くか、ユーザー名とパスワードが通るかだけを確かめるコンソールツールです。認証が済んだところで切断するので、Mac側にはセッションもカーテンもできません。`--negotiate`を付けると映像の設定のやり取りまで進めるので、Macに一瞬セッションができ、カーテンがかかります。

```powershell
iss-check.exe --host mac.local --user me              # パスワードを伏せ字で尋ねる
iss-check.exe --host mac.local --user me --negotiate
```

終了コードは、0が認証成功、1が接続できない・画面共有ではない・認証が途中で切れた、2がユーザー名かパスワードの拒否、3が引数の誤りです。確かめられるのはTCP 5900のやり取りまでで、映像のUDPが通るかどうかは分かりません。

## テスト

`./build.ps1 -Test`でユニットテストを実行します。暗号、RFB、zlibなどのテストベクタ（`tests/vectors.inc`）はPython版の実装から作っているので、Python側を変えたら作り直してください。iShareScreenの依存パッケージを入れたPythonで、iShareScreenの`src`を`PYTHONPATH`に入れて実行します。

```powershell
$env:PYTHONPATH = "..\iShareScreen\src"
python tools\gen_vectors.py
```

## ライセンス

iss-winはiShareScreen（AGPL-3.0-or-later）の移植なので、同じGNU Affero General Public License v3.0以降で公開します。全文は[LICENSE](LICENSE)にあります。標準モードの「適応」の形式は[rootshell-vnc](https://github.com/kitknox/rootshell-vnc)（MIT）に従いました。ほかの出典も含め、[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)にまとめています。
