#!/usr/bin/env bash
set -euo pipefail

CYAN='\033[0;36m'
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UV_BIN_DIR="$HOME/.local/bin"

echo -e "${CYAN}Installing SoloSec...${NC}"

OS="$(uname -s)"
case "$OS" in
	Linux*)  OS_TYPE="Linux" ;;
	Darwin*) OS_TYPE="Mac" ;;
	*)       echo -e "${RED}Unsupported OS: $OS${NC}"; exit 1 ;;
esac
echo "   Detected: $OS_TYPE"

if ! command -v docker >/dev/null 2>&1; then
	echo -e "${RED}Missing requirement: Docker. Please install it first.${NC}"
	exit 1
fi

if ! command -v uv >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing uv...${NC}"
	curl -LsSf https://astral.sh/uv/install.sh | sh
fi

export PATH="$UV_BIN_DIR:$PATH"

echo -e "${CYAN}[*] Checking dependency tools...${NC}"
if ! command -v trivy >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing Trivy...${NC}"
	if [ "$OS_TYPE" = "Mac" ]; then
		if command -v brew >/dev/null 2>&1; then
			brew install trivy
		else
			echo -e "${RED}   Homebrew not found. Please install Trivy manually: https://trivy.dev${NC}"
		fi
	else
		curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin
	fi
else
	echo -e "${GREEN}   -> Trivy already installed.${NC}"
fi

if ! command -v gitleaks >/dev/null 2>&1; then
	echo -e "${YELLOW}   -> Installing Gitleaks...${NC}"
	if [ "$OS_TYPE" = "Mac" ]; then
		if command -v brew >/dev/null 2>&1; then
			brew install gitleaks
		else
			echo -e "${RED}   Homebrew not found. Please install Gitleaks manually: https://github.com/gitleaks/gitleaks${NC}"
		fi
	else
		GITLEAKS_VERSION=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest | grep '"tag_name"' | sed -E 's/.*"v([^"]+)".*/\1/')
		curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" | tar -xz -C /usr/local/bin gitleaks
	fi
else
	echo -e "${GREEN}   -> Gitleaks already installed.${NC}"
fi

echo -e "${CYAN}[*] Installing SoloSec with uv...${NC}"
uv python install 3.11
uv tool install --force --python 3.11 -e "$SCRIPT_DIR"

if [ -n "$ZSH_VERSION" ] || [ "$SHELL" = "/bin/zsh" ]; then
	SHELL_RC="$HOME/.zshrc"
elif [ -n "$BASH_VERSION" ] || [ "$SHELL" = "/bin/bash" ]; then
	SHELL_RC="$HOME/.bashrc"
else
	SHELL_RC="$HOME/.profile"
fi

if [[ ":$PATH:" != *":$UV_BIN_DIR:"* ]]; then
	echo -e "${CYAN}[*] Adding '$UV_BIN_DIR' to your PATH...${NC}"
	echo "" >> "$SHELL_RC"
	echo "# SoloSec / uv tools" >> "$SHELL_RC"
	echo "export PATH=\"$UV_BIN_DIR:\$PATH\"" >> "$SHELL_RC"
	echo -e "${GREEN}Added to $SHELL_RC${NC}"
	echo -e "${YELLOW}Restart your terminal or run: source $SHELL_RC${NC}"
else
	echo -e "${GREEN}uv tool bin directory is already on PATH.${NC}"
fi

echo ""
echo -e "${GREEN}Installation complete!${NC}"
echo -e "Run ${CYAN}solosec${NC} from any project directory to start a security audit."
