# Third-party notices

## iShareScreen

iss-win is a C++ port of iShareScreen (https://github.com/Chapoly1305/iShareScreen), licensed under the GNU Affero General Public License v3.0 or later. The protocol handling follows its Python implementation, and `tests/vectors.inc` is generated from it (`tools/gen_vectors.py`). iss-win is distributed under the same license; see `LICENSE`.

## rootshell-vnc

`src/session/apple_dct.cpp` decodes Apple's DCT codec (RFB encoding 1011) following the bitstream format as implemented by rootshell-vnc's `AppleAdaptiveDCTDecoder` (https://github.com/kitknox/rootshell-vnc).

```
MIT License

Copyright (c) 2026 Rootshell LLC, Kit Knox

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

## stb_image

The integer IDCT and YCbCr conversion in `src/session/apple_dct.cpp` follow stb_image by Sean Barrett (https://github.com/nothings/stb), which is in the public domain (or MIT licensed, at your choice).

## FFmpeg

iss-win links dynamically against an LGPL shared build of FFmpeg 8.1 (https://ffmpeg.org/), placed in `third_party/ffmpeg/` at build time. FFmpeg is not included in this repository; the builds used come from BtbN/FFmpeg-Builds (https://github.com/BtbN/FFmpeg-Builds), configured with `--enable-version3` (LGPL v3). Its DLLs are copied next to the executables, and its license is in the build's `LICENSE.txt`.
