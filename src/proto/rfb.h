// RFB 3.889（RFC 6143 + Appleの独自メッセージ）。定数と、issが送る
// クライアント → サーバーのメッセージ。protocol/rfb.pyとapple.pyの移植。
#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "core/bytes.h"

namespace iss::rfb {

inline constexpr char kProtocolVersion[] = "RFB 003.889\n";  // 回線上では12バイト

// サーバー → クライアント（enc1103の復号後）。
inline constexpr uint8_t SRV_FRAMEBUFFER_UPDATE = 0x00;
inline constexpr uint8_t SRV_SET_COLOR_MAP_ENTRIES = 0x01;
inline constexpr uint8_t SRV_BELL = 0x02;
inline constexpr uint8_t SRV_SERVER_CUT_TEXT = 0x03;
inline constexpr uint8_t SRV_USER_SESSION_CHANGED = 0x14;  // Apple独自

// クライアント → サーバー。
inline constexpr uint8_t CLI_SET_ENCODINGS = 0x02;
inline constexpr uint8_t CLI_KEY_EVENT = 0x04;
inline constexpr uint8_t CLI_POINTER_EVENT = 0x05;
inline constexpr uint8_t CLI_POST_ENCRYPTION_TOGGLE = 0x12;
inline constexpr uint8_t CLI_MEDIA_NEGOTIATION = 0x1C;
inline constexpr uint8_t CLI_VIRTUAL_DISPLAY = 0x1D;
inline constexpr uint8_t CLI_VIEWER_INFO = 0x21;

// AppleのHPエンコーディング一覧。enc1103のトグル前に平文で送り、トグル後に
// 暗号化してもう一度送る。-239（旧来のRichCursor）はわざと外している。カーソルには
// キャッシュつきの擬似エンコーディング1104だけを使う。
inline const std::vector<int32_t> kHpEncodingsFull = {
    1010, 1011, 1002, 6, 16, 1104, 1100, -223, 1101, 1105, 1107, 1109, 1110,
};

// AppleのポインタボタンマスクはRFC 6143とくらべてbit 1とbit 2が入れ替わっている。
inline constexpr uint8_t BTN_LEFT = 1 << 0;
inline constexpr uint8_t BTN_RIGHT = 1 << 1;
inline constexpr uint8_t BTN_MIDDLE = 1 << 2;
inline constexpr uint8_t BTN_SCROLL_UP = 1 << 3;
inline constexpr uint8_t BTN_SCROLL_DOWN = 1 << 4;

// ── Appleハンドシェイクの定数（apple.py） ─────────────────────────────────

// 32バイトのViewerInfoコマンドマスク。Screen Sharing.appが立てる機能ゲート
// （画像のクリップボード、クリップボードのプッシュ、2.1秒のtickleなど）。
std::array<uint8_t, 32> apple_viewer_command_mask();
// ローカルのOSに関係なくViewerInfoで示すmacOSのバージョン。
inline constexpr std::array<uint32_t, 3> kAppleViewerOsVer = {15, 3, 0};
// 平文フェーズでViewerInfoの直後に送る12バイトの0x12フォローアップ。
// フィールドが全ビット1であることに意味がある。全部0にするとハンドシェイクに失敗する。
Bytes apple_0x12_followup();

// ── ビルダー ─────────────────────────────────────────────────────────────

Bytes build_set_encodings(const std::vector<int32_t>& encodings = kHpEncodingsFull);
Bytes build_post_encryption_toggle();
Bytes build_key_event(bool down, uint32_t keysym);
Bytes build_pointer_event(uint8_t buttons, int x, int y);
Bytes build_viewer_info(uint32_t app_id, std::array<uint32_t, 3> app_ver, std::array<uint32_t, 3> os_ver,
                        const std::array<uint8_t, 32>& command_mask, const Bytes& extra = {});
// Screen Sharing.appが送るViewerInfo（app 2、v6.1.0）と0x12フォローアップ。
Bytes build_default_viewer_info_with_followup();

struct VirtualDisplayParams {
  int width = 1920;           // 論理（ポイント）サイズ
  int height = 1080;
  double hidpi_scale = 2.0;   // バッキング:ポイントの比（小数もありうる）
  bool hdr = false;
  std::string display_name = "iShareScreen Virtual Display";
  int mode_count = 5;
  bool alt_user_login = false;  // 今のところバイト列には影響しない（rfb.py参照）
  // ディスクリプタの最大バッキングサイズ。Screen Sharing.appは3840x2160を送る。
  int max_width = 3840;
  int max_height = 2160;
};
// 仮想ディスプレイ1台分、`second`があれば2台分（Screen Sharingの
// numVirtualDisplays。高パフォーマンスなら2台まで）のディスクリプタをそれぞれ作る。
// Macは2台目を1台目の右に置き、0x1cが2本目をオファーしていれば
// 2本目のビデオストリーム（UDPポート + 2）として流す。
Bytes build_virtual_display(const VirtualDisplayParams& p, const VirtualDisplayParams* second = nullptr);

Bytes build_fbu_request(bool incremental, uint16_t x = 0, uint16_t y = 0, uint16_t w = 0xFFFF,
                        uint16_t h = 0xFFFF);
// AutoFrameBufferUpdate（0x09）。以後はホストがその領域の更新を自分から
// 送ってくる。screen 0xffffffffは全体またはメイン（§8.11）。
Bytes build_auto_fbu(uint16_t x, uint16_t y, uint16_t w, uint16_t h, uint32_t screen = 0xffffffff);

// 結合したバッキングキャンバス内での、ホストのディスプレイ1台分の矩形
// （AppleDisplayLayout、enc 0x451）。ディスプレイは要求した順に並ぶ。
// バッキングキャンバスと、ディスプレイごとに1本ずつのビデオストリームは、
// Mac側のディスプレイ配置どおりに左から右へ並ぶので、2台目のディスプレイが
// 1台目より左に来ることもある。
struct DisplayRect {
  uint32_t display_id;
  int x, y, w, h;  // バッキングのピクセル
  int px = 0, py = 0, pw = 0, ph = 0;  // ポイント（グローバルなディスプレイ範囲）
};
struct DisplayLayout {
  int backing_w = 0, backing_h = 0;
  std::vector<DisplayRect> rects;
};
bool parse_apple_display_layout(const uint8_t* p, size_t n, DisplayLayout& out);

}  // namespace iss::rfb
