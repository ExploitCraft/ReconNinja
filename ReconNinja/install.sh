#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════════╗
# ║              ReconNinja v3.3 — Installer                                   ║
# ║              https://github.com/ExploitCraft/ReconNinja                    ║
# ╚══════════════════════════════════════════════════════════════════════════════╝
# Supports: Kali · Ubuntu · Debian · Parrot · Arch · Manjaro · Fedora · CentOS
#           Rocky · AlmaLinux · openSUSE · Alpine · macOS (Homebrew)
# Does NOT support: Windows (use WSL2)
#
# What this script does:
#   1. Detects OS and blocks Windows
#   2. Installs Python deps (rich)
#   3. Copies tool to ~/.reconninja/ (dot folder in home)
#   4. Creates alias  'ReconNinja'  → python3 ~/.reconninja/reconninja.py
#   5. Installs all optional recon tools (nmap, rustscan, go tools, etc.)
#
# Usage:
#   chmod +x install.sh && ./install.sh
#   ./install.sh --skip-go       # skip Go tools
#   ./install.sh --skip-rust     # skip RustScan
#   ./install.sh --python-only   # only Python deps + copy + alias

set -euo pipefail

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m'

# ── Flags ─────────────────────────────────────────────────────────────────────
SKIP_GO=false
SKIP_RUST=false
PYTHON_ONLY=false

for arg in "$@"; do
    case $arg in
        --skip-go)      SKIP_GO=true ;;
        --skip-rust)    SKIP_RUST=true ;;
        --python-only)  PYTHON_ONLY=true; SKIP_GO=true; SKIP_RUST=true ;;
    esac
done

# ── Helpers ───────────────────────────────────────────────────────────────────
ok()   { echo -e "${GREEN}  ✔${NC}  $*"; }
warn() { echo -e "${YELLOW}  ⚠${NC}  $*"; }
err()  { echo -e "${RED}  ✘${NC}  $*"; }
info() { echo -e "${CYAN}  ▶${NC}  $*"; }
step() { echo -e "\n${BOLD}${CYAN}── $* ──${NC}"; }
cmd_exists() { command -v "$1" &>/dev/null; }

install_go_tool() {
    local bin="$1" pkg="$2"
    if cmd_exists "$bin"; then
        ok "$bin already installed"
    else
        info "Installing $bin..."
        go install "$pkg" 2>&1 | tail -1 && ok "$bin installed" \
            || warn "$bin install failed — install manually"
    fi
}

# ── Banner ────────────────────────────────────────────────────────────────────
echo ""
echo -e "${CYAN}${BOLD}"
cat << 'BANNER'
██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗███╗   ██╗██╗███╗   ██╗     ██╗ █████╗
██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║████╗  ██║██║████╗  ██║     ██║██╔══██╗
██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║██╔██╗ ██║██║██╔██╗ ██║     ██║███████║
██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║██║╚██╗██║██║██║╚██╗██║██   ██║██╔══██║
██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║██║ ╚████║██║██║ ╚████║╚█████╔╝██║  ██║
╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚════╝ ╚═╝  ╚═╝
BANNER
echo -e "${NC}"
echo -e "${BOLD}  ReconNinja v3.3 — Installer${NC}"
echo -e "${DIM}  https://github.com/ExploitCraft/ReconNinja${NC}"
echo ""
echo -e "${RED}  ⚠  Use ONLY against targets you own or have written permission to test.${NC}"
echo ""

# ── Windows block ─────────────────────────────────────────────────────────────
if [[ "${OSTYPE:-}" == "msys" || "${OSTYPE:-}" == "cygwin" || \
      "${OSTYPE:-}" == "win32" || -n "${WINDIR:-}" ]]; then
    err "Windows is not supported."
    echo ""
    echo "  Please use WSL2 (Windows Subsystem for Linux):"
    echo "  https://learn.microsoft.com/en-us/windows/wsl/install"
    echo ""
    exit 1
fi

# ── OS / package manager detection ───────────────────────────────────────────
step "Detecting OS"

DISTRO="unknown"
PKG_MGR="unknown"
IS_MACOS=false

if [[ "$(uname -s)" == "Darwin" ]]; then
    IS_MACOS=true
    DISTRO="macos"
    PKG_MGR="brew"
    ok "macOS detected"
elif [[ -f /etc/os-release ]]; then
    source /etc/os-release
    DISTRO="${ID:-unknown}"
    case "${ID:-}" in
        kali|ubuntu|debian|parrot|linuxmint|pop)
            PKG_MGR="apt"; ok "Detected: ${PRETTY_NAME:-$ID} (apt)" ;;
        arch|manjaro|endeavouros|garuda)
            PKG_MGR="pacman"; ok "Detected: ${PRETTY_NAME:-$ID} (pacman)" ;;
        fedora|centos|rhel|rocky|almalinux)
            PKG_MGR="dnf"; ok "Detected: ${PRETTY_NAME:-$ID} (dnf)" ;;
        opensuse*|sles)
            PKG_MGR="zypper"; ok "Detected: ${PRETTY_NAME:-$ID} (zypper)" ;;
        alpine)
            PKG_MGR="apk"; ok "Detected: Alpine Linux (apk)" ;;
        *)
            # Fallback — probe which package manager exists
            if   cmd_exists apt-get; then PKG_MGR="apt"
            elif cmd_exists pacman;  then PKG_MGR="pacman"
            elif cmd_exists dnf;     then PKG_MGR="dnf"
            elif cmd_exists yum;     then PKG_MGR="yum"
            elif cmd_exists zypper;  then PKG_MGR="zypper"
            elif cmd_exists apk;     then PKG_MGR="apk"
            fi
            warn "Unknown distro '$DISTRO' — using $PKG_MGR"
            ;;
    esac
else
    warn "Cannot read /etc/os-release — probing package managers..."
    if   cmd_exists apt-get; then PKG_MGR="apt"
    elif cmd_exists pacman;  then PKG_MGR="pacman"
    elif cmd_exists dnf;     then PKG_MGR="dnf"
    elif cmd_exists brew;    then PKG_MGR="brew"; IS_MACOS=true
    else warn "No known package manager found — some tools may not install"
    fi
fi

# ── pkg_install helper — works on any supported OS ───────────────────────────
pkg_install() {
    local pkg="$1"
    case "$PKG_MGR" in
        apt)    sudo apt-get install -y -qq "$pkg" ;;
        pacman) sudo pacman -S --noconfirm "$pkg" ;;
        dnf)    sudo dnf install -y "$pkg" ;;
        yum)    sudo yum install -y "$pkg" ;;
        zypper) sudo zypper install -y "$pkg" ;;
        apk)    sudo apk add --no-cache "$pkg" ;;
        brew)   brew install "$pkg" ;;
        *)      warn "Cannot auto-install $pkg — unknown package manager"; return 1 ;;
    esac
}

pkg_update() {
    case "$PKG_MGR" in
        apt)    sudo apt-get update -qq ;;
        pacman) sudo pacman -Sy --noconfirm ;;
        dnf)    sudo dnf check-update -q || true ;;
        brew)   brew update ;;
        apk)    sudo apk update ;;
        *)      true ;;
    esac
}

# ── Python check ──────────────────────────────────────────────────────────────
step "Python 3.10+"

PYTHON=""
for py in python3.12 python3.11 python3.10 python3; do
    if cmd_exists "$py"; then
        _maj=$("$py" -c 'import sys; print(sys.version_info.major)')
        _min=$("$py" -c 'import sys; print(sys.version_info.minor)')
        if [[ "$_maj" -ge 3 && "$_min" -ge 10 ]]; then
            PYTHON="$py"
            ok "$py (${_maj}.${_min}) found"
            break
        fi
    fi
done

if [[ -z "$PYTHON" ]]; then
    err "Python 3.10+ not found. Install from https://www.python.org/downloads/"
    exit 1
fi

# pip
PIP=""
for pip in pip3 pip; do
    if cmd_exists "$pip"; then PIP="$pip"; break; fi
done
if [[ -z "$PIP" ]]; then
    info "pip not found — installing..."
    pkg_install python3-pip && PIP="pip3" || { err "pip install failed"; exit 1; }
fi

# ── Install pip deps ──────────────────────────────────────────────────────────
step "Python dependencies"
info "Installing rich..."
$PIP install -r "$(dirname "$0")/requirements.txt" --break-system-packages -q 2>/dev/null \
    || $PIP install rich -q 2>/dev/null \
    || { err "pip install rich failed"; exit 1; }
ok "rich installed"

# ── Create ~/.reconninja/ dot folder ─────────────────────────────────────────
step "Creating ~/.reconninja/ installation folder"

INSTALL_DIR="$HOME/.reconninja"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ -d "$INSTALL_DIR" ]]; then
    warn "~/.reconninja already exists — updating..."
else
    info "Creating $INSTALL_DIR ..."
    mkdir -p "$INSTALL_DIR"
    ok "Created $INSTALL_DIR"
fi

# Copy all tool files into ~/.reconninja/
info "Copying ReconNinja files → $INSTALL_DIR ..."
cp -r "$SCRIPT_DIR/." "$INSTALL_DIR/"
chmod +x "$INSTALL_DIR/reconninja.py"
ok "Files copied to $INSTALL_DIR"

# ── Create alias 'ReconNinja' ─────────────────────────────────────────────────
step "Creating 'ReconNinja' alias"

ALIAS_LINE="alias ReconNinja='$PYTHON $INSTALL_DIR/reconninja.py'"
ALIAS_COMMENT="# ReconNinja v3.3 — https://github.com/ExploitCraft/ReconNinja"

# Detect which shell config files to write to
SHELL_CONFIGS=()

# Current user's default shell
DEFAULT_SHELL="$(basename "${SHELL:-/bin/bash}")"

# Always try to write to all that exist
[[ -f "$HOME/.bashrc"   ]] && SHELL_CONFIGS+=("$HOME/.bashrc")
[[ -f "$HOME/.bash_profile" ]] && SHELL_CONFIGS+=("$HOME/.bash_profile")
[[ -f "$HOME/.zshrc"    ]] && SHELL_CONFIGS+=("$HOME/.zshrc")
[[ -f "$HOME/.zprofile" ]] && SHELL_CONFIGS+=("$HOME/.zprofile")
[[ -f "$HOME/.config/fish/config.fish" ]] && SHELL_CONFIGS+=("$HOME/.config/fish/config.fish")

# If nothing found yet, create the right one based on current shell
if [[ ${#SHELL_CONFIGS[@]} -eq 0 ]]; then
    case "$DEFAULT_SHELL" in
        zsh)  touch "$HOME/.zshrc";   SHELL_CONFIGS+=("$HOME/.zshrc") ;;
        fish) mkdir -p "$HOME/.config/fish"
              touch "$HOME/.config/fish/config.fish"
              SHELL_CONFIGS+=("$HOME/.config/fish/config.fish") ;;
        *)    touch "$HOME/.bashrc";  SHELL_CONFIGS+=("$HOME/.bashrc") ;;
    esac
fi

# Write alias to each config file
ALIAS_WRITTEN=false
for cfg_file in "${SHELL_CONFIGS[@]}"; do
    if grep -q "alias ReconNinja=" "$cfg_file" 2>/dev/null; then
        # Update existing alias
        if [[ "$(uname -s)" == "Darwin" ]]; then
            sed -i '' "s|alias ReconNinja=.*|${ALIAS_LINE}|g" "$cfg_file"
        else
            sed -i "s|alias ReconNinja=.*|${ALIAS_LINE}|g" "$cfg_file"
        fi
        ok "Updated alias in $cfg_file"
    else
        {
            echo ""
            echo "$ALIAS_COMMENT"
            echo "$ALIAS_LINE"
        } >> "$cfg_file"
        ok "Alias added to $cfg_file"
    fi
    ALIAS_WRITTEN=true
done

# Fish shell needs different syntax
if [[ -f "$HOME/.config/fish/config.fish" ]]; then
    FISH_ALIAS="alias ReconNinja '$PYTHON $INSTALL_DIR/reconninja.py'"
    if grep -q "alias ReconNinja" "$HOME/.config/fish/config.fish" 2>/dev/null; then
        sed -i "s|alias ReconNinja.*|${FISH_ALIAS}|g" "$HOME/.config/fish/config.fish"
    else
        {
            echo ""
            echo "# ReconNinja v3.3"
            echo "$FISH_ALIAS"
        } >> "$HOME/.config/fish/config.fish"
    fi
    ok "Fish alias added to ~/.config/fish/config.fish"
fi

# Also create a standalone wrapper script in ~/.local/bin so it works even
# in shells where aliases aren't loaded (cron, scripts, etc.)
WRAPPER_DIR="$HOME/.local/bin"
mkdir -p "$WRAPPER_DIR"
cat > "$WRAPPER_DIR/ReconNinja" << WRAPPER
#!/usr/bin/env bash
# ReconNinja v3.3 wrapper — auto-generated by install.sh
exec $PYTHON $INSTALL_DIR/reconninja.py "\$@"
WRAPPER
chmod +x "$WRAPPER_DIR/ReconNinja"
ok "Wrapper script created at $WRAPPER_DIR/ReconNinja"

# Add ~/.local/bin to PATH if not already there
for cfg_file in "${SHELL_CONFIGS[@]}"; do
    if ! grep -q "\.local/bin" "$cfg_file" 2>/dev/null; then
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$cfg_file"
        ok "Added ~/.local/bin to PATH in $cfg_file"
    fi
done
export PATH="$HOME/.local/bin:$PATH"

if $ALIAS_WRITTEN; then
    echo ""
    echo -e "  ${BOLD}After install, activate the alias with:${NC}"
    echo -e "  ${CYAN}  source ~/.bashrc${NC}    (bash)"
    echo -e "  ${CYAN}  source ~/.zshrc${NC}     (zsh)"
    echo -e "  ${CYAN}  source ~/.config/fish/config.fish${NC}  (fish)"
    echo ""
    echo -e "  Then run:  ${GREEN}${BOLD}ReconNinja${NC}"
fi

# ── Early exit for --python-only ──────────────────────────────────────────────
if $PYTHON_ONLY; then
    echo ""
    ok "Python-only install complete."
    echo -e "  Run: ${CYAN}ReconNinja --check-tools${NC}"
    echo ""
    exit 0
fi

# ── Update package lists ──────────────────────────────────────────────────────
step "Updating package lists"
pkg_update || warn "Package list update failed — continuing anyway"

# ── System tools: nmap, masscan, nikto, whatweb ───────────────────────────────
step "System tools (nmap · masscan · nikto · whatweb)"

declare -A PKG_MAP_APT=(   [nmap]=nmap     [masscan]=masscan [nikto]=nikto [whatweb]=whatweb )
declare -A PKG_MAP_PACMAN=([nmap]=nmap     [masscan]=masscan [nikto]=nikto [whatweb]=whatweb )
declare -A PKG_MAP_DNF=(   [nmap]=nmap     [masscan]=masscan [nikto]=nikto )   # whatweb not in default repos
declare -A PKG_MAP_BREW=(  [nmap]=nmap     [nikto]=nikto )                     # masscan/whatweb via brew cask

for tool in nmap masscan nikto whatweb; do
    if cmd_exists "$tool"; then
        ok "$tool already installed"
        continue
    fi
    info "Installing $tool..."
    pkg_install "$tool" 2>/dev/null && ok "$tool installed" \
        || warn "$tool not available in repos — skip"
done

# ── SecLists ──────────────────────────────────────────────────────────────────
step "SecLists wordlists"

SECLISTS_PATHS=("/usr/share/seclists" "/usr/share/SecLists" "$HOME/SecLists" "/opt/SecLists")
SECLISTS_FOUND=false
for p in "${SECLISTS_PATHS[@]}"; do
    if [[ -d "$p" ]]; then
        ok "SecLists found at $p"; SECLISTS_FOUND=true; break
    fi
done

if ! $SECLISTS_FOUND; then
    if [[ "$PKG_MGR" == "apt" ]]; then
        info "Installing SecLists via apt..."
        pkg_install seclists 2>/dev/null && ok "SecLists installed" || {
            warn "apt seclists failed — cloning from GitHub (~900MB)..."
            sudo git clone --depth 1 https://github.com/danielmiessler/SecLists.git \
                /usr/share/seclists 2>/dev/null && ok "SecLists cloned" \
                || warn "SecLists install failed — built-in wordlist will be used"
        }
    else
        warn "SecLists not found — install manually:"
        echo "       git clone https://github.com/danielmiessler/SecLists ~/SecLists"
    fi
fi

# ── Go tools ──────────────────────────────────────────────────────────────────
if ! $SKIP_GO; then
    step "Go language"

    if ! cmd_exists go; then
        info "Go not found — installing..."
        if [[ "$PKG_MGR" == "apt" ]]; then
            pkg_install golang-go 2>/dev/null && ok "Go installed" || {
                err "Go install failed. Get it from: https://go.dev/dl/"
                warn "Skipping all Go tools"
                SKIP_GO=true
            }
        elif [[ "$PKG_MGR" == "brew" ]]; then
            brew install go && ok "Go installed" || { warn "Go install failed"; SKIP_GO=true; }
        elif [[ "$PKG_MGR" == "pacman" ]]; then
            pkg_install go && ok "Go installed" || { warn "Go install failed"; SKIP_GO=true; }
        elif [[ "$PKG_MGR" == "dnf" ]]; then
            pkg_install golang && ok "Go installed" || { warn "Go install failed"; SKIP_GO=true; }
        else
            err "Go not found. Install from: https://go.dev/dl/"
            SKIP_GO=true
        fi
    else
        ok "Go $(go version | awk '{print $3}') found"
    fi

    if ! $SKIP_GO; then
        export PATH="$PATH:$(go env GOPATH)/bin"
        mkdir -p "$(go env GOPATH)/bin"

        step "Go recon tools"
        install_go_tool "subfinder"   "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
        install_go_tool "httpx"       "github.com/projectdiscovery/httpx/cmd/httpx@latest"
        install_go_tool "nuclei"      "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
        install_go_tool "ffuf"        "github.com/ffuf/ffuf/v2@latest"
        install_go_tool "assetfinder" "github.com/tomnomnom/assetfinder@latest"
        install_go_tool "gowitness"   "github.com/sensepost/gowitness@latest"

        info "Installing amass (may take a minute)..."
        if cmd_exists amass; then
            ok "amass already installed"
        else
            go install github.com/owasp-amass/amass/v4/...@master 2>&1 | tail -1 \
                && ok "amass installed" || warn "amass install failed"
        fi

        # Persist GOPATH/bin in all detected shell configs
        GOBIN="$(go env GOPATH)/bin"
        for cfg_file in "${SHELL_CONFIGS[@]}"; do
            if ! grep -q "$(go env GOPATH)/bin" "$cfg_file" 2>/dev/null; then
                echo "export PATH=\"\$PATH:$GOBIN\"" >> "$cfg_file"
                ok "GOPATH/bin added to PATH in $cfg_file"
            fi
        done
    fi
fi

# ── RustScan ──────────────────────────────────────────────────────────────────
if ! $SKIP_RUST; then
    step "RustScan (primary port scanner)"

    if cmd_exists rustscan; then
        ok "RustScan already installed"
    elif cmd_exists cargo; then
        info "Installing RustScan via cargo..."
        cargo install rustscan && ok "RustScan installed" || warn "cargo install failed"
    else
        info "Rust not found — trying pre-built binary..."
        ARCH=$(uname -m)
        RS_DEB=""
        case "$ARCH" in
            x86_64)  RS_DEB="rustscan_amd64.deb" ;;
            aarch64) RS_DEB="rustscan_arm64.deb"  ;;
        esac

        if [[ -n "$RS_DEB" && "$PKG_MGR" == "apt" ]]; then
            TMP=$(mktemp /tmp/rustscan_XXXXXX.deb)
            curl -fsSL \
                "https://github.com/RustScan/RustScan/releases/latest/download/$RS_DEB" \
                -o "$TMP" 2>/dev/null \
            && sudo dpkg -i "$TMP" && ok "RustScan installed from .deb" \
            || warn "RustScan .deb install failed"
            rm -f "$TMP"
        elif [[ "$PKG_MGR" == "brew" ]]; then
            brew install rustscan && ok "RustScan installed" || warn "brew install failed"
        else
            warn "Cannot auto-install RustScan on this OS"
            echo "  Install Rust: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh"
            echo "  Then: cargo install rustscan"
        fi
    fi
fi

# ── feroxbuster ───────────────────────────────────────────────────────────────
step "feroxbuster (directory scanner)"

if cmd_exists feroxbuster; then
    ok "feroxbuster already installed"
elif [[ "$PKG_MGR" == "apt" ]]; then
    pkg_install feroxbuster 2>/dev/null && ok "feroxbuster installed" || {
        info "apt failed — using curl installer..."
        curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
            | bash -s "$HOME/.local/bin" 2>/dev/null \
            && ok "feroxbuster installed to ~/.local/bin" \
            || warn "feroxbuster install failed — ffuf/dirsearch will be used"
    }
elif [[ "$PKG_MGR" == "brew" ]]; then
    brew install feroxbuster && ok "feroxbuster installed" || warn "feroxbuster install failed"
else
    warn "feroxbuster not available — ffuf/dirsearch will be used as fallback"
fi

# ── dirsearch ─────────────────────────────────────────────────────────────────
step "dirsearch (directory scanner fallback)"

if cmd_exists dirsearch; then
    ok "dirsearch already installed"
else
    $PIP install dirsearch --break-system-packages -q 2>/dev/null \
        || $PIP install dirsearch -q 2>/dev/null \
        && ok "dirsearch installed" \
        || warn "dirsearch install failed"
fi

# ── Nuclei templates ──────────────────────────────────────────────────────────
step "Nuclei templates"

if cmd_exists nuclei; then
    info "Updating nuclei templates..."
    nuclei -update-templates -silent 2>/dev/null \
        && ok "Nuclei templates updated" \
        || ok "Templates will download on first run"
else
    warn "nuclei not installed — vuln scanning will be skipped"
fi

# ── Final tool check ──────────────────────────────────────────────────────────
step "Final tool check"
echo ""
"$PYTHON" "$INSTALL_DIR/reconninja.py" --check-tools
echo ""

# ── Done ──────────────────────────────────────────────────────────────────────
echo -e "${GREEN}${BOLD}"
echo "  ╔═════════════════════════════════════════════════════════════╗"
echo "  ║                                                             ║"
echo "  ║   ✔  ReconNinja v3.3 installed to ~/.reconninja/            ║"
echo "  ║   ✔  Alias 'ReconNinja' created in your shell config        ║"
echo "  ║   ✔  Wrapper script at ~/.local/bin/ReconNinja              ║"
echo "  ║                                                             ║"
echo "  ║   To start using RIGHT NOW (without restarting terminal):   ║"
echo "  ║                                                             ║"
echo "  ║     source ~/.bashrc   OR   source ~/.zshrc                 ║"
echo "  ║       OR source your fish config if you use fish or OTHER   ║"
echo "  ║   Then just type: ReconNinja                                ║"
echo "  ║                                                             ║"
echo "  ║   Docs: https://github.com/ExploitCraft/ReconNinja          ║"
echo "  ╚═════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo -e "${RED}  ⚠  Only scan systems you own or have written permission to test.${NC}"
echo ""
