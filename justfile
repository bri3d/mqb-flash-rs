# VW Flash RS — build recipes
#
# On Windows, just invokes PowerShell instead of sh so that MSVC link.exe
# takes precedence over any GNU tools on PATH (avoids Git Bash linker conflict).
set windows-shell := ["powershell.exe", "-NoLogo", "-Command"]

x64 := "x86_64-pc-windows-msvc"
x86 := "i686-pc-windows-msvc"

# List available recipes
default:
    @just --list

# Compile-check both targets
check:
    cargo check --workspace --target {{x64}}
    cargo check --workspace --target {{x86}}

# Run tests (x64 only — tests are hardware-free)
test:
    cargo test --workspace --target {{x64}}

# Build 64-bit release binaries (CLI + GUI + Logger + A2L Viewer)
build-x64:
    cargo build --release --package mqb-flash-cli --package mqb-flash-gui --package mqb-logger-gui --package mqb-a2l-viewer --target {{x64}}

# Build 32-bit release binaries (CLI + GUI)
# First-time setup: rustup target add i686-pc-windows-msvc
build-x86:
    cargo build --release --package mqb-flash-cli --package mqb-flash-gui --target {{x86}}

# Build CLI + GUI for both architectures
build: build-x64 build-x86

# Build both and stage to dist/
dist: build
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    Copy-Item target/{{x64}}/release/mqb-flash.exe     dist/mqb-flash-x64.exe     -Force
    Copy-Item target/{{x86}}/release/mqb-flash.exe     dist/mqb-flash-x86.exe     -Force
    Copy-Item target/{{x64}}/release/mqb-flash-gui.exe  dist/mqb-flash-gui-x64.exe  -Force
    Copy-Item target/{{x86}}/release/mqb-flash-gui.exe  dist/mqb-flash-gui-x86.exe  -Force
    Copy-Item target/{{x64}}/release/mqb-logger-gui.exe  dist/mqb-logger-gui-x64.exe  -Force
    Copy-Item target/{{x64}}/release/mqb-a2l-viewer.exe dist/mqb-a2l-viewer-x64.exe -Force
    @Write-Host "dist/ is ready: mqb-flash-{x64,x86}.exe, mqb-flash-gui-{x64,x86}.exe, mqb-logger-gui-x64.exe, mqb-a2l-viewer-x64.exe"
