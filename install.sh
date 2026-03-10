#!/bin/bash

set -e

REPO_RAW="https://raw.githubusercontent.com/azizultex/ai-plugin-review-skills/main"
COMMANDS=("wp-plugin-review.md" "wp-security-scan.md")

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo ""
echo "WordPress Plugin Review Skills for Claude Code"
echo "================================================"
echo ""
echo "Where do you want to install?"
echo "  1) Global — available in all your projects (~/.claude/commands/)"
echo "  2) Project — only in the current directory (./.claude/commands/)"
echo ""
read -rp "Enter 1 or 2 [default: 1]: " choice

case "$choice" in
  2)
    INSTALL_DIR="$(pwd)/.claude/commands"
    echo ""
    echo "Installing into current project: $INSTALL_DIR"
    ;;
  *)
    INSTALL_DIR="$HOME/.claude/commands"
    echo ""
    echo "Installing globally: $INSTALL_DIR"
    ;;
esac

mkdir -p "$INSTALL_DIR"

for file in "${COMMANDS[@]}"; do
  dest="$INSTALL_DIR/$file"
  echo "  Downloading $file..."

  if curl -fsSL "$REPO_RAW/.claude/commands/$file" -o "$dest"; then
    echo -e "  ${GREEN}Done${NC} → $dest"
  else
    echo "  Error: Could not download $file. Check your internet connection or the repo URL."
    exit 1
  fi
done

echo ""
echo -e "${GREEN}Skills installed successfully.${NC}"
echo ""
echo "Available commands in Claude Code:"
echo -e "  ${YELLOW}/wp-plugin-review${NC}  — Full 30-category compliance and security audit"
echo -e "  ${YELLOW}/wp-security-scan${NC}  — Focused 12-category security vulnerability scan"
echo ""

if [ "$INSTALL_DIR" = "$HOME/.claude/commands" ]; then
  echo "Open any plugin directory in Claude Code and run the commands."
else
  echo "Open this directory in Claude Code and run the commands."
fi

echo ""
