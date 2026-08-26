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

# Reformat every crate
fmt:
    cargo fmt --all

# Point git at the versioned hooks in .githooks/ (run once per clone)
install-hooks:
    git config core.hooksPath .githooks

# Verify formatting without changing anything (what CI enforces)
fmt-check:
    cargo fmt --all --check

# Lint with warnings as errors (what CI enforces)
clippy:
    cargo clippy --workspace --all-targets -- -D warnings

# An ordinary `cargo check` never compiles the feature-gated j2534 adapters, so
# their cfg gate can rot unnoticed. The socketcan equivalent is Linux-only and
# is covered in CI instead.

# Compile the feature-gated j2534 adapters
check-j2534:
    cargo check -p mqb-flash-uds --features j2534 --all-targets --target {{x64}}
    cargo check -p mqb-immo-gui --features j2534 --all-targets --target {{x64}}

# Everything CI gates on, in one command. Run this before pushing.
ci: fmt-check clippy test check-j2534

# Build 64-bit release binaries (CLI + Flash GUI + Immo GUI + Logger + A2L Viewer)
build-x64:
    cargo build --release --package mqb-flash-cli --package mqb-flash-gui --package mqb-immo-gui --package mqb-logger-gui --package mqb-a2l-viewer --features mqb-flash-cli/j2534,mqb-flash-gui/j2534,mqb-immo-gui/j2534 --target {{x64}}

# First-time setup: rustup target add i686-pc-windows-msvc

# Build 32-bit release binaries (CLI + Flash GUI + Immo GUI)
#
# The 32-bit builds exist for J2534: a PassThru DLL can only be loaded by a
# process of its own architecture, and several vendors ship 32-bit only. Both
# GUIs that open a J2534 device therefore need an x86 build.
build-x86:
    cargo build --release --package mqb-flash-cli --package mqb-flash-gui --package mqb-immo-gui --features mqb-flash-cli/j2534,mqb-flash-gui/j2534,mqb-immo-gui/j2534 --target {{x86}}

# Build every shipped binary for both architectures
build: build-x64 build-x86

# Build both and stage to dist/
dist: build
    New-Item -ItemType Directory -Force -Path dist | Out-Null
    Copy-Item target/{{x64}}/release/mqb-flash.exe     dist/mqb-flash-x64.exe     -Force
    Copy-Item target/{{x86}}/release/mqb-flash.exe     dist/mqb-flash-x86.exe     -Force
    Copy-Item target/{{x64}}/release/mqb-flash-gui.exe  dist/mqb-flash-gui-x64.exe  -Force
    Copy-Item target/{{x86}}/release/mqb-flash-gui.exe  dist/mqb-flash-gui-x86.exe  -Force
    Copy-Item target/{{x64}}/release/mqb-immo.exe       dist/mqb-immo-x64.exe       -Force
    Copy-Item target/{{x86}}/release/mqb-immo.exe       dist/mqb-immo-x86.exe       -Force
    Copy-Item target/{{x64}}/release/mqb-logger-gui.exe  dist/mqb-logger-gui-x64.exe  -Force
    Copy-Item target/{{x64}}/release/mqb-a2l-viewer.exe dist/mqb-a2l-viewer-x64.exe -Force
    @Write-Host "dist/ is ready: mqb-flash-{x64,x86}.exe, mqb-flash-gui-{x64,x86}.exe, mqb-immo-{x64,x86}.exe, mqb-logger-gui-x64.exe, mqb-a2l-viewer-x64.exe"
