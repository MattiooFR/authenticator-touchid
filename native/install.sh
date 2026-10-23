#!/bin/sh
# Installe l'hôte Touch ID pour Chrome (utilisateur courant, sans sudo).
set -eu
cd "$(dirname "$0")"

NAME=com.authenticator.touchid
EXTENSION_ID=pmbilcebaiegkjgcjhobcmkcaiafddon
DEST="$HOME/Library/Application Support/AuthenticatorTouchID"
BIN="$DEST/authenticator-touchid"

mkdir -p "$DEST"
swiftc -O main.swift -o "$BIN"
codesign --force --sign - --identifier "$NAME" "$BIN"

# Chrome (et Chrome Beta/Canary, Brave, Edge s'ils sont là)
for BROWSER in "Google/Chrome" "Google/Chrome Beta" "Google/Chrome Canary" "BraveSoftware/Brave-Browser" "Microsoft Edge" "Chromium"; do
  ROOT="$HOME/Library/Application Support/$BROWSER"
  [ -d "$ROOT" ] || continue
  mkdir -p "$ROOT/NativeMessagingHosts"
  cat > "$ROOT/NativeMessagingHosts/$NAME.json" <<JSON
{
  "name": "$NAME",
  "description": "Touch ID pour l'extension Authenticator",
  "path": "$BIN",
  "type": "stdio",
  "allowed_origins": ["chrome-extension://$EXTENSION_ID/"]
}
JSON
  echo "✓ $BROWSER"
done
echo "Installé : $BIN"
