#!/bin/bash
# Build static OpenSSL for mingw-w64 cross-compilation
# This creates a "vendored" OpenSSL like Rust's openssl crate

set -e

OPENSSL_VERSION="3.5.4"
INSTALL_PREFIX="/opt/openssl-mingw64-static"
BUILD_DIR="/tmp/openssl-build"

echo "=== Building Static OpenSSL for mingw-w64 ==="
echo "Version: $OPENSSL_VERSION"
echo "Install prefix: $INSTALL_PREFIX"
echo ""

# Check if already installed
if [ -f "$INSTALL_PREFIX/lib/libssl.a" ] && [ -f "$INSTALL_PREFIX/lib/libcrypto.a" ]; then
    echo "✓ Static OpenSSL already installed at $INSTALL_PREFIX"
    echo "  libssl.a: $(ls -lh $INSTALL_PREFIX/lib/libssl.a | awk '{print $5}')"
    echo "  libcrypto.a: $(ls -lh $INSTALL_PREFIX/lib/libcrypto.a | awk '{print $5}')"
    exit 0
fi

# Create build directory
mkdir -p $BUILD_DIR
cd $BUILD_DIR

# Download OpenSSL if not already present
if [ ! -f "openssl-$OPENSSL_VERSION.tar.gz" ]; then
    echo "Downloading OpenSSL $OPENSSL_VERSION..."
    wget -q --show-progress https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
fi

# Extract
echo "Extracting..."
rm -rf openssl-$OPENSSL_VERSION
tar -xzf openssl-$OPENSSL_VERSION.tar.gz
cd openssl-$OPENSSL_VERSION

# Configure for mingw-w64 static build
echo "Configuring for mingw-w64 (static libraries only)..."
./Configure mingw64 \
    --cross-compile-prefix=x86_64-w64-mingw32- \
    --prefix=$INSTALL_PREFIX \
    no-shared \
    no-asm \
    -static

# Build
echo "Building (this may take 5-10 minutes)..."
make -j$(nproc)

# Install
echo "Installing to $INSTALL_PREFIX..."
sudo make install_sw install_ssldirs

# Verify installation
echo ""
echo "=== Installation Complete ==="
echo "Static libraries installed:"
ls -lh $INSTALL_PREFIX/lib/libssl.a
ls -lh $INSTALL_PREFIX/lib/libcrypto.a
echo ""
echo "Include files installed at: $INSTALL_PREFIX/include"
echo ""
echo "To use these libraries, rsa.nim has been configured with the correct paths."
echo "Simply rebuild your agent and OpenSSL will be statically linked!"

# Cleanup
cd /
rm -rf $BUILD_DIR

echo ""
echo "✓ Done! You can now build poopsie with statically linked OpenSSL."
