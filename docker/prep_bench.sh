#!/usr/bin/env bash
# 把 chellenges/ 原始文件整理成 bench/<ch>/ 标准结构：bin + 可选 libc/ld
set -e
cd /work/chellenges
BENCH=/work/bench
rm -rf "$BENCH"; mkdir -p "$BENCH"

mk() { mkdir -p "$BENCH/$1"; }

mk ch01_note;     cp 090d11f498589c83ac1593ce9ea29d2f01ba6612f6c30c52f70dfa04bd650594 "$BENCH/ch01_note/bin"
mk ch02_x86_4d79; cp 4d795e433de55363045711fc0c241e1fae8233998ff862d255f5be29744bde46 "$BENCH/ch02_x86_4d79/bin"
mk ch03_58a4;     cp 58a4f4983f17b7b554580683106b2249a91a45060072cc191f6db4531231738c "$BENCH/ch03_58a4/bin"
mk ch04_5ff0;     cp 5ff02fcf132226f17fdbbfbc55454a4cf4b1eda0b88c49dd5a5844c03d901a3e "$BENCH/ch04_5ff0/bin"
mk ch05_82cf;     cp 82cfdbe697d9dd2282a32637b40e88a05b4b6158b8a5ee84cc897dee8f2c5f4b "$BENCH/ch05_82cf/bin"
mk ch06_8835;     cp 883530626036942b273c8d5078a146eb2c1c42cf80fc9b291d6d6c544a3fe277 "$BENCH/ch06_8835/bin"
mk ch07_acae;     cp acae6f3ae89a552fa1f0fe2759c788082117838503c406c5d3b9b97b034b8153 "$BENCH/ch07_acae/bin"
mk ch08_b69c;     cp b69ca4681a3d6d87c422f574e761e9a99ba2d1f5025d20a89695bc8594e1a543 "$BENCH/ch08_b69c/bin"
mk ch09_cf87;     cp cf87893f7b19a099b23a7ddaeb922a3c675a5d93fb91e4bd04a90f30f552eddd "$BENCH/ch09_cf87/bin"
mk ch10_static32; cp d5288a1ad6a1d3fb49a4612cdfb0d8ee8cfc2c54bfe0d7a4589806425742638d "$BENCH/ch10_static32/bin"
mk ch11_fd2e;     cp fd2e7f0a164a1d8cb8f2500e784fc08bff9ff95bb8468d5bc55e948097b192e7 "$BENCH/ch11_fd2e/bin"

mkdir -p "$BENCH/ch12_zip3143" "$BENCH/ch13_zip76c8" "$BENCH/ch14_easyheap" "$BENCH/ch15_zip_e62d"
unzip -oq 3143f4e2c5a80d8bb026956f7a0abae4a412beaee7c07edb5ae26ef8b5c19e5e.zip -d "$BENCH/ch12_zip3143"
unzip -oq 76c83755bd304a590d0b7826c56917c9c3bf8310968690f5cdcd36d51814cdc1.zip -d "$BENCH/ch13_zip76c8"
unzip -oq b42eb603c33c68ead8aca66b96d6f323934f4bb93b39c1793318dafa2f9e277f.zip -d "$BENCH/ch14_easyheap"
unzip -oq e62d040119be5e6fa2e5b16d07eb3001f4a77198823f80a65cd83c513774de37.zip -d "$BENCH/ch15_zip_e62d"
rm -rf "$BENCH/ch14_easyheap/__MACOSX"

mv "$BENCH/ch12_zip3143/pwn" "$BENCH/ch12_zip3143/bin"
mv "$BENCH/ch15_zip_e62d/pwn" "$BENCH/ch15_zip_e62d/bin"
mv "$BENCH/ch13_zip76c8/pwn"  "$BENCH/ch13_zip76c8/bin"
mv "$BENCH/ch14_easyheap/easyheap" "$BENCH/ch14_easyheap/bin"

for d in "$BENCH"/ch*; do
  chmod +x "$d/bin" 2>/dev/null || true
  if ls "$d"/libc*.so >/dev/null 2>&1; then
    mkdir -p "$d/libc"; mv "$d"/libc*.so "$d/libc/"
  fi
  if ls "$d"/ld-*.so >/dev/null 2>&1; then
    mkdir -p "$d/libc"; mv "$d"/ld-*.so "$d/libc/"
  fi
done

find "$BENCH" -type f | sort
