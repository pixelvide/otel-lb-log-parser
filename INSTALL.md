# Installing Go on macOS

## Option 1: Install with Homebrew (Recommended)

```bash
# Install Homebrew if you don't have it
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install Go
brew install go

# Verify installation
go version
```

## Option 2: Download Official Binary

1. Visit: https://go.dev/dl/
2. Download the macOS installer (.pkg file)
3. Run the installer
4. Verify installation:
   ```bash
   go version
   ```

## After Installation

Set up your environment (add to `~/.zshrc`):

```bash
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin
```

Then reload:
```bash
source ~/.zshrc
```

## Test the Go ALB Parser

Once installed, run:

```bash
cd /Users/ngoyal16/pixelvide/devops/cloud-sentinel/go-alb-processor
go mod download
go test ./pkg/parser -v
go test -bench=. ./pkg/parser
```
