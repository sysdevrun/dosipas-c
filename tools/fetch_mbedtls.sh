#!/bin/sh
# Download and build libmbedcrypto for host builds of dosipas-c.
#
#   tools/fetch_mbedtls.sh [tag] [dest]
#
# tag:  mbedTLS git tag, default v3.6.4 (also tested: v2.28.10, the version the
#       ESP32 Arduino core 2.0.17 ships).
# dest: install prefix, default .deps/mbedtls-<tag> next to this repository.
#
# Produces <dest>/include/mbedtls/*.h and <dest>/lib/libmbedcrypto.a. Idempotent:
# exits immediately when the library already exists.
set -eu

TAG="${1:-v3.6.4}"
HERE="$(cd "$(dirname "$0")/.." && pwd)"
DEST="${2:-$HERE/.deps/mbedtls-$TAG}"
CMAKE="${CMAKE:-$(command -v cmake || echo "$HOME/.platformio/packages/tool-cmake/bin/cmake")}"

if [ -f "$DEST/lib/libmbedcrypto.a" ]; then
    echo "mbedtls $TAG already built in $DEST"
    exit 0
fi

mkdir -p "$DEST"
SRC="$DEST/src"
if [ ! -d "$SRC/library" ]; then
    echo "cloning mbedtls $TAG"
    rm -rf "$SRC"
    git clone --quiet --depth 1 --branch "$TAG" https://github.com/Mbed-TLS/mbedtls.git "$SRC"
    # 3.6 keeps part of its build system in a submodule.
    (cd "$SRC" && git submodule update --quiet --init --depth 1 2>/dev/null || true)
fi

echo "building libmbedcrypto ($TAG) with $CMAKE"
"$CMAKE" -S "$SRC" -B "$DEST/build" \
    -DCMAKE_BUILD_TYPE=Release \
    -DENABLE_TESTING=OFF -DENABLE_PROGRAMS=OFF \
    -DUSE_SHARED_MBEDTLS_LIBRARY=OFF -DUSE_STATIC_MBEDTLS_LIBRARY=ON \
    -DGEN_FILES=OFF \
    -DCMAKE_INSTALL_PREFIX="$DEST" >"$DEST/configure.log" 2>&1 || {
    cat "$DEST/configure.log"
    exit 1
}
"$CMAKE" --build "$DEST/build" --target mbedcrypto -j >"$DEST/build.log" 2>&1 || {
    tail -50 "$DEST/build.log"
    exit 1
}
mkdir -p "$DEST/lib" "$DEST/include"
cp "$DEST/build/library/libmbedcrypto.a" "$DEST/lib/"
cp -R "$SRC/include/mbedtls" "$DEST/include/"
[ -d "$SRC/include/psa" ] && cp -R "$SRC/include/psa" "$DEST/include/"
[ -d "$SRC/tf-psa-crypto/include" ] && cp -R "$SRC/tf-psa-crypto/include/." "$DEST/include/"
echo "mbedtls $TAG installed in $DEST"
