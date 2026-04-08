#!/bin/bash

echo "╔══════════════════════════════════════════════════════╗"
echo "║   Ultimate Web Security Scanner v2.0 Installer       ║"
echo "║   Multi-Language High-Performance Architecture       ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Check prerequisites
echo -e "${BLUE}[*] Checking prerequisites...${NC}"

# Python
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version | cut -d' ' -f2)
    echo -e "${GREEN}[✓] Python ${PYTHON_VERSION} found${NC}"
else
    echo -e "${RED}[✗] Python 3.8+ required${NC}"
    exit 1
fi

# Golang
if command -v go &> /dev/null; then
    GO_VERSION=$(go version | cut -d' ' -f3)
    echo -e "${GREEN}[✓] Golang ${GO_VERSION} found${NC}"
    GOLANG_ENABLED=true
else
    echo -e "${YELLOW}[!] Golang not found - Golang modules will be disabled${NC}"
    GOLANG_ENABLED=false
fi

# Rust
if command -v rustc &> /dev/null; then
    RUST_VERSION=$(rustc --version | cut -d' ' -f2)
    echo -e "${GREEN}[✓] Rust ${RUST_VERSION} found${NC}"
    RUST_ENABLED=true
else
    echo -e "${YELLOW}[!] Rust not found - Rust modules will be disabled${NC}"
    RUST_ENABLED=false
fi

# Ruby
if command -v ruby &> /dev/null; then
    RUBY_VERSION=$(ruby --version | cut -d' ' -f2)
    echo -e "${GREEN}[✓] Ruby ${RUBY_VERSION} found${NC}"
    RUBY_ENABLED=true
else
    echo -e "${YELLOW}[!] Ruby not found - Ruby modules will be disabled${NC}"
    RUBY_ENABLED=false
fi

echo ""

# Install Python dependencies
echo -e "${BLUE}[*] Installing Python dependencies...${NC}"
pip3 install -r requirements.txt
if [ $? -eq 0 ]; then
    echo -e "${GREEN}[✓] Python dependencies installed${NC}"
else
    echo -e "${RED}[✗] Failed to install Python dependencies${NC}"
    exit 1
fi

# Create bin directory
mkdir -p bin

# Build Golang modules
if [ "$GOLANG_ENABLED" = true ]; then
    echo -e "${BLUE}[*] Building Golang modules...${NC}"
    cd golang-modules
    go mod init goscan 2>/dev/null
    go mod tidy
    go build -o ../bin/goscan ./cmd/goscan
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}[✓] Golang modules built${NC}"
    else
        echo -e "${RED}[✗] Failed to build Golang modules${NC}"
    fi
    cd ..
fi

# Build Rust modules
if [ "$RUST_ENABLED" = true ]; then
    echo -e "${BLUE}[*] Building Rust modules...${NC}"
    cd rust-modules
    cargo build --release
    if [ $? -eq 0 ]; then
        cp target/release/rustscan ../bin/
        echo -e "${GREEN}[✓] Rust modules built${NC}"
    else
        echo -e "${RED}[✗] Failed to build Rust modules${NC}"
    fi
    cd ..
fi

# Install Ruby dependencies
if [ "$RUBY_ENABLED" = true ]; then
    echo -e "${BLUE}[*] Installing Ruby dependencies...${NC}"
    gem install json
    echo -e "${GREEN}[✓] Ruby dependencies installed${NC}"
    echo -e "${YELLOW}[!] For full Ruby functionality, install Metasploit Framework${NC}"
fi

# Make scanner executable
chmod +x scanner.py

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   Installation Complete!                             ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${BLUE}Enabled Engines:${NC}"
[ "$GOLANG_ENABLED" = true ] && echo -e "  ${GREEN}✓ Golang${NC}" || echo -e "  ${RED}✗ Golang${NC}"
[ "$RUST_ENABLED" = true ] && echo -e "  ${GREEN}✓ Rust${NC}" || echo -e "  ${RED}✗ Rust${NC}"
[ "$RUBY_ENABLED" = true ] && echo -e "  ${GREEN}✓ Ruby${NC}" || echo -e "  ${RED}✗ Ruby${NC}"
echo -e "  ${GREEN}✓ Python${NC}"
echo ""
echo -e "${BLUE}Quick Start:${NC}"
echo -e "  ${YELLOW}./scanner.py https://example.com${NC}"
echo -e "  ${YELLOW}./scanner.py https://example.com --mode golang${NC}"
echo -e "  ${YELLOW}./scanner.py https://example.com --fuzzer rust${NC}"
echo ""
echo -e "${BLUE}For more information:${NC}"
echo -e "  ${YELLOW}./scanner.py --help${NC}"
echo ""
