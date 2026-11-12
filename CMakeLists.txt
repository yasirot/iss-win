cmake_minimum_required(VERSION 3.24)
project(iss-win LANGUAGES CXX)

if(NOT MSVC)
  message(FATAL_ERROR "iss-win is built with MSVC (run build.ps1 or a VS developer shell)")
endif()

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

add_compile_definitions(UNICODE _UNICODE WIN32_LEAN_AND_MEAN NOMINMAX _WIN32_WINNT=0x0A00)
add_compile_options(/W4 /permissive- /utf-8 /EHsc /MP)

set(FFMPEG_ROOT ${CMAKE_SOURCE_DIR}/third_party/ffmpeg CACHE PATH "FFmpeg shared build (include/ lib/ bin/)")

# ── core: プロトコル、暗号、通信（UIは含まない） ─────────────────────────
add_library(iss_core STATIC
  src/core/bytes.cpp
  src/core/log.cpp
  src/crypto/bigint.cpp
  src/crypto/crypto.cpp
  src/net/tcp.cpp
  src/net/udp.cpp
  src/proto/auth.cpp
  src/proto/check.cpp
  src/proto/negotiation.cpp
  src/proto/offers.cpp
  src/proto/rfb.cpp
  src/proto/rtcp.cpp
  src/proto/srtp.cpp
  src/proto/enc1103.cpp
  src/util/zlib.cpp
  src/util/bplist.cpp
  src/input/input_mapper.cpp
  src/input/keyboard_grab.cpp
)
target_include_directories(iss_core PUBLIC src)
target_link_libraries(iss_core PUBLIC ws2_32 bcrypt crypt32)

# ── media: NALの再構成とFFmpegでのデコード ───────────────────────────────
add_library(iss_media STATIC
  src/media/hevc_refs.cpp
  src/media/nalu.cpp
  src/media/video_decoder.cpp
)
target_include_directories(iss_media PUBLIC src PRIVATE ${FFMPEG_ROOT}/include)
target_link_directories(iss_media PUBLIC ${FFMPEG_ROOT}/lib)
target_link_libraries(iss_media PUBLIC iss_core avcodec avutil swscale)
# FFmpegのヘッダーでMSVCの/W4警告がいくつか出る。上流のコードなのでこちらでは直せない。
target_compile_options(iss_media PRIVATE /wd4244)

# ── session: UDPのメディア経路、RTP → デコーダー、RTCPフィードバック ─────
add_library(iss_session STATIC
  src/session/apple_dct.cpp
  src/session/control_messages.cpp
  src/session/framebuffer.cpp
  src/session/picture_assembler.cpp
  src/session/rtp_grouper.cpp
  src/session/session.cpp
)
target_include_directories(iss_session PUBLIC src)
target_link_libraries(iss_session PUBLIC iss_core iss_media)

# ── iss-win: Win32のUIとD3D11のビューア ──────────────────────────────────
add_executable(iss-win WIN32
  src/app/main.cpp
  src/app/connect_dialog.cpp
  src/app/credentials.cpp
  src/app/renderer.cpp
  src/app/player.cpp
  src/app/iss-win.rc
  src/app/iss-win.manifest
)
target_link_libraries(iss-win PRIVATE iss_session d3d11 dxgi d3dcompiler comctl32 shell32 ole32 advapi32 wtsapi32)

# ── iss-check: コンソールの接続チェック（TCP、RFBハンドシェイク、認証） ──
add_executable(iss-check src/app/check_main.cpp)
target_link_libraries(iss-check PRIVATE iss_core)

# ── テスト ───────────────────────────────────────────────────────────────
enable_testing()
add_executable(iss-tests tests/test_main.cpp)
target_link_libraries(iss-tests PRIVATE iss_session)
target_compile_definitions(iss-tests PRIVATE ISS_TEST_DATA_DIR="${CMAKE_SOURCE_DIR}/tests/data")
add_test(NAME unit COMMAND iss-tests)

# FFmpegのDLLを実行ファイルの隣に置く。
if(EXISTS ${FFMPEG_ROOT}/bin)
  file(GLOB FFMPEG_DLLS ${FFMPEG_ROOT}/bin/*.dll)
  foreach(t iss-win iss-tests)
    add_custom_command(TARGET ${t} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E copy_if_different ${FFMPEG_DLLS} $<TARGET_FILE_DIR:${t}>)
  endforeach()
endif()
