#!/bin/bash

# =============================================================================
# CONFIGURATION (Environment Variables)
# =============================================================================

# ANDROID (.apk) configuration
#
# Two env vars:
#   ANDROID_KEYSTORE  — absolute path to the .jks/.keystore file
#   ANDROID_KEYPROPS  — absolute path to a key.properties file containing:
#                          storePassword=...
#                          keyPassword=...
#                          keyAlias=...
#
# If ANDROID_KEYPROPS is unset, falls back to ANDROID_ALIAS / ANDROID_PASS /
# ANDROID_KEY_PASS env vars (ANDROID_KEY_PASS defaults to ANDROID_PASS).
: "${ANDROID_KEYSTORE:=$HOME/share/android.keystore}"
: "${ANDROID_KEYPROPS:=}"
: "${ANDROID_ALIAS:=my-alias}"
: "${ANDROID_PASS:=password}"
: "${ANDROID_KEY_PASS:=$ANDROID_PASS}"

# Load credentials from key.properties if ANDROID_KEYPROPS is set.
# Values from the file override the env-var defaults above.
if [[ -n "$ANDROID_KEYPROPS" ]]; then
    if [[ ! -f "$ANDROID_KEYPROPS" ]]; then
        echo "ANDROID_KEYPROPS file not found: $ANDROID_KEYPROPS" >&2
        exit 1
    fi

    # Permission check — keyprops contains plaintext passwords, must be owner-only.
    # macOS uses BSD stat (-f %A); Linux uses GNU stat (-c %a). Both return octal.
    if [[ "$(uname)" == "Darwin" ]]; then
        _kp_mode=$(stat -f %A "$ANDROID_KEYPROPS" 2>/dev/null)
    else
        _kp_mode=$(stat -c %a "$ANDROID_KEYPROPS" 2>/dev/null)
    fi
    # Normalise to 3 digits (some stats emit 4 like "0600").
    [[ "${#_kp_mode}" == 4 ]] && _kp_mode="${_kp_mode:1}"
    # Refuse if the file is readable by group or other (any non-zero in the last two digits).
    if [[ -n "$_kp_mode" && "${_kp_mode:1}" != "00" ]]; then
        echo "[ERROR] $ANDROID_KEYPROPS has permissions ${_kp_mode} — group or other can read it." >&2
        echo "        This file contains plaintext signing passwords and must be owner-only." >&2
        echo "        Fix:  chmod 600 \"$ANDROID_KEYPROPS\"" >&2
        exit 1
    fi

    _kp_store=$(awk -F= '$1=="storePassword"{sub(/^[^=]*=/,""); sub(/\r$/,""); print; exit}' "$ANDROID_KEYPROPS")
    _kp_key=$(awk -F=   '$1=="keyPassword"{sub(/^[^=]*=/,"");   sub(/\r$/,""); print; exit}' "$ANDROID_KEYPROPS")
    _kp_alias=$(awk -F= '$1=="keyAlias"{sub(/^[^=]*=/,"");      sub(/\r$/,""); print; exit}' "$ANDROID_KEYPROPS")
    [[ -n "$_kp_store" ]] && ANDROID_PASS="$_kp_store"
    [[ -n "$_kp_key"   ]] && ANDROID_KEY_PASS="$_kp_key"
    [[ -n "$_kp_alias" ]] && ANDROID_ALIAS="$_kp_alias"
fi

# WINDOWS (.msix) configuration
: "${WINDOWS_P12:=$HOME/share/self-signed.p12}"
: "${WINDOWS_PASS:=password}"
: "${WINDOWS_CERT:=$HOME/cert.pem}"

# MACOS (.dmg) configuration
: "${MAC_P12:=$HOME/share/self-signed.p12}"
: "${MAC_PASS:=password}"
# The Common Name (CN) used when generating your cert (e.g. "Subterfuge")
: "${MAC_CERT_SUBJECT:=My App}"

# LINUX (.AppImage) configuration
: "${GPG_KEY_ID:=my@email.com}"
: "${GPG_PASS:=passphrase}"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

function show_help {
    echo -e "${BLUE}Multi-Platform Signing Tool${NC}"
    echo "Usage: $(basename "$0") <command> [flags] <file>"
    echo ""
    echo "Commands:"
    echo "  sign    Sign the provided file."
    echo "  verify  Verify the provided file."
    echo ""
    echo "Sign flags:"
    echo "  -xaab   With <file.aab>: also extract a signed universal (fat) APK via bundletool."
    echo ""
    echo "Current Configuration:"
    echo "  MAC_CERT_SUBJECT : $MAC_CERT_SUBJECT"
    echo "  MAC_P12 : $MAC_P12"
    echo "  ANDROID_KEYSTORE : $ANDROID_KEYSTORE"
    echo "  ANDROID_KEYPROPS : ${ANDROID_KEYPROPS:-<not set — using ANDROID_ALIAS / ANDROID_PASS env vars>}"
    echo ""
    echo -e "${YELLOW}=== HOW TO GENERATE SOLID SIGNING KEYS ===${NC}"

    echo -e "${GREEN}[1] Android (Production Grade)${NC}"
    echo "  # Generates a 4096-bit RSA key in PKCS12 format (Industry Standard)"
    echo "  keytool -genkeypair -v \\"
    echo "    -keystore android.keystore \\"
    echo "    -storetype PKCS12 \\"
    echo "    -keyalg RSA -keysize 4096 -sigalg SHA256withRSA \\"
    echo "    -validity 10000 \\"
    echo "    -alias my-alias \\"
    echo "    -dname \"CN=My App, OU=Engineering, O=My Company, L=City, ST=State, C=FR\""
    echo ""

    echo -e "${GREEN}[2] Windows & macOS (.p12 + .pem)${NC}"
    echo "  # Step A: Generate 4096-bit Key and Certificate"
    echo "  openssl req -x509 -newkey rsa:4096 -sha256 \\"
    echo "    -keyout key.pem -out cert.pem -days 3650 -nodes \\"
    echo "    -subj \"/CN=My App/O=My Company/C=FR\""
    echo "  # Step B: Bundle into PKCS12 (Universal Format)"
    echo "  # Note: Uses legacy encryption to ensure compatibility with rcodesign"
    echo "  openssl pkcs12 -export -out self-signed.p12 -inkey key.pem -in cert.pem \\"
    echo "    -legacy -descert -keypbe PBE-SHA1-3DES -certpbe PBE-SHA1-3DES"
    echo ""


    echo -e "${GREEN}[3] Linux (.AppImage GPG)${NC}"
    echo "  # Generates an RSA 4096-bit key that never expires"
    echo "  # Usage: 'rsa4096' (Algo) 'default' (Sign/Cert/Encr) '0' (No Expiry)"
    echo "  gpg --batch --passphrase 'passphrase' --quick-gen-key my@email.com rsa4096 default 0"
    echo ""

    exit 1
}


function log_info {
    echo -e "${BLUE}[INFO]${NC} $1"
}

function log_success {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

function log_error {
    echo -e "${RED}[ERROR]${NC} $1"
    exit 1
}

function log_warn {
    echo -e "${YELLOW:-\033[0;33m}[WARN]${NC} $1" >&2
}

# Soft check: the .jks itself is password-encrypted, but a world/group-readable
# keystore is still a smell. Warn (don't fail) so the user knows to tighten it.
function _warn_loose_keystore_perms {
    local f="$1"
    [[ -f "$f" ]] || return 0
    local mode
    if [[ "$(uname)" == "Darwin" ]]; then
        mode=$(stat -f %A "$f" 2>/dev/null)
    else
        mode=$(stat -c %a "$f" 2>/dev/null)
    fi
    [[ "${#mode}" == 4 ]] && mode="${mode:1}"
    if [[ -n "$mode" && "${mode:1}" != "00" ]]; then
        log_warn "$f has permissions $mode — group/other can read this keystore."
        echo "       The .jks is password-encrypted, but tighten with: chmod 600 \"$f\"" >&2
    fi
}

# =============================================================================
# MAIN LOGIC
# =============================================================================

COMMAND="${1:-}"
shift 2>/dev/null || true

# Optional flag parsing (must come before <file>):
#   -xaab   only valid with `sign <aab>` — also extracts a universal APK via bundletool.
EXTRACT_APK=0
if [[ "${1:-}" == "-xaab" ]]; then
    EXTRACT_APK=1
    shift
fi

FILE="${1:-}"

if [[ -z "$COMMAND" || -z "$FILE" ]]; then show_help; fi
if [[ ! -f "$FILE" ]]; then log_error "File not found: $FILE"; fi

EXT="${FILE##*.}"
EXT="${EXT,,}"
BASENAME="${FILE%.*}"

if [[ "$EXTRACT_APK" == "1" && "$EXT" != "aab" ]]; then
    log_error "-xaab is only valid with .aab files (got .$EXT)"
fi
if [[ "$EXTRACT_APK" == "1" && "$COMMAND" != "sign" ]]; then
    log_error "-xaab is only valid with the 'sign' command"
fi
# Fail fast on -xaab if bundletool isn't installed — we don't want to sign the
# AAB and then bail mid-flow when extraction kicks in, leaving the user with a
# signed AAB but no APK.
if [[ "$EXTRACT_APK" == "1" ]] && ! command -v bundletool >/dev/null 2>&1; then
    echo -e "${RED}[ERROR]${NC} bundletool not installed — required for -xaab." >&2
    echo "        Install it first, then re-run paraph:" >&2
    echo "          macOS:  brew install bundletool" >&2
    echo "          Linux:  download bundletool-all.jar from https://github.com/google/bundletool/releases" >&2
    echo "                  and wrap as a 'bundletool' command on your PATH" >&2
    exit 1
fi

case "$COMMAND" in
    sign)
        case "$EXT" in
            apk)
                log_info "Signing Android APK..."
                OUT_FILE="${BASENAME}-signed.apk"
                if [[ ! -f "$ANDROID_KEYSTORE" ]]; then
                    log_error "Keystore not found: $ANDROID_KEYSTORE (set ANDROID_KEYSTORE to the correct path)"
                fi
                _warn_loose_keystore_perms "$ANDROID_KEYSTORE"
                if command -v zipalign >/dev/null 2>&1; then
                    if ! zipalign -c 4 "$FILE" >/dev/null 2>&1; then
                        log_error "APK is not zipaligned. Fix with: zipalign -p 4 \"$FILE\" \"${BASENAME}-aligned.apk\" (then sign the -aligned.apk)"
                    fi
                else
                    log_info "zipalign not on PATH — skipping alignment check"
                fi
                apksigner sign --ks "$ANDROID_KEYSTORE" --ks-key-alias "$ANDROID_ALIAS" --ks-pass "pass:$ANDROID_PASS" --key-pass "pass:$ANDROID_KEY_PASS" --out "$OUT_FILE" "$FILE" && log_success "Created $OUT_FILE" || log_error "Failed"
                ;;
            aab)
                log_info "Signing Android AAB..."
                OUT_FILE="${BASENAME}-signed.aab"
                if [[ ! -f "$ANDROID_KEYSTORE" ]]; then
                    log_error "Keystore not found: $ANDROID_KEYSTORE (set ANDROID_KEYSTORE to the correct path)"
                fi
                _warn_loose_keystore_perms "$ANDROID_KEYSTORE"
                if ! command -v jarsigner >/dev/null 2>&1; then
                    log_error "jarsigner not found — install a JDK (java 8+) and ensure jarsigner is on PATH"
                fi
                # AABs are signed with jarsigner, NOT apksigner. -signedjar writes a separate output
                # leaving the input untouched. -sigalg/-digestalg force SHA-256 (default is SHA-1
                # on older JDKs, which Play Console rejects).
                jarsigner -keystore "$ANDROID_KEYSTORE" -storepass "$ANDROID_PASS" -keypass "$ANDROID_KEY_PASS" -sigalg SHA256withRSA -digestalg SHA-256 -signedjar "$OUT_FILE" "$FILE" "$ANDROID_ALIAS" && log_success "Created $OUT_FILE" || log_error "AAB sign failed"

                # -xaab: also extract a signed universal (fat) APK from the AAB via bundletool.
                # bundletool always signs the APKs it produces; we pass the same keystore so the
                # output APK is signed with the upload key (same one apksigner would use for APKs).
                if [[ "$EXTRACT_APK" == "1" ]]; then
                    log_info "Extracting universal APK via bundletool..."
                    APKS_ZIP="${BASENAME}.apks"
                    APK_OUT="${BASENAME}-signed.apk"
                    TMPD=$(mktemp -d)
                    bundletool build-apks \
                        --bundle="$FILE" \
                        --output="$APKS_ZIP" \
                        --mode=universal \
                        --overwrite \
                        --ks="$ANDROID_KEYSTORE" \
                        --ks-pass="pass:$ANDROID_PASS" \
                        --ks-key-alias="$ANDROID_ALIAS" \
                        --key-pass="pass:$ANDROID_KEY_PASS" \
                        || { rm -rf "$TMPD" "$APKS_ZIP"; log_error "bundletool build-apks failed"; }
                    unzip -oq "$APKS_ZIP" universal.apk -d "$TMPD" \
                        || { rm -rf "$TMPD" "$APKS_ZIP"; log_error "could not extract universal.apk from $APKS_ZIP"; }
                    mv "$TMPD/universal.apk" "$APK_OUT"
                    rm -rf "$TMPD" "$APKS_ZIP"
                    log_success "Created $APK_OUT (universal fat APK — all ABIs)"
                fi
                ;;
            msix)
                log_info "Signing Windows MSIX..."
                OUT_FILE="${BASENAME}-signed.msix"
                osslsigncode sign -pkcs12 "$WINDOWS_P12" -pass "$WINDOWS_PASS" -in "$FILE" -out "$OUT_FILE" && log_success "Created $OUT_FILE" || log_error "Failed"
                ;;
            dmg)
                log_info "Signing macOS DMG..."
                OUT_FILE="${BASENAME}-signed.dmg"
                cp "$FILE" "$OUT_FILE"
                rcodesign sign --p12-file "$MAC_P12" --p12-password "$MAC_PASS" --code-signature-flags runtime "$OUT_FILE" && log_success "Signed $OUT_FILE" || log_error "Failed"
                ;;
            appimage)
                log_info "Signing Linux AppImage..."
                # Added: --pinentry-mode loopback
                # This tells GPG: "Don't try to open a GUI/Text window, just take the pipe input"
                echo "$GPG_PASS" | gpg --batch --yes --pinentry-mode loopback --passphrase-fd 0 --local-user "$GPG_KEY_ID" --detach-sig --output "$FILE.sig" "$FILE"
                [ $? -eq 0 ] && log_success "Created $FILE.sig" || log_error "Failed"
                ;;

        esac
        ;;

    verify)
        case "$EXT" in
            apk)
                if command -v zipalign >/dev/null 2>&1; then
                    if ! zipalign -c 4 "$FILE" >/dev/null 2>&1; then
                        log_error "APK is not zipaligned. Fix with: zipalign -p 4 \"$FILE\" \"${BASENAME}-aligned.apk\" then re-sign and re-verify the -aligned.apk"
                    fi
                else
                    log_info "zipalign not on PATH — skipping alignment check"
                fi
                apksigner verify --print-certs "$FILE"
                ;;
            aab)
                if ! command -v jarsigner >/dev/null 2>&1; then
                    log_error "jarsigner not found — install a JDK (java 8+)"
                fi
                jarsigner -verify -verbose -certs "$FILE"
                ;;
            msix)
                if [ -f "$WINDOWS_CERT" ]; then
                    osslsigncode verify -CAfile "$WINDOWS_CERT" -in "$FILE"
                else
                    log_info "No CAfile found, checking structure only..."
                    osslsigncode verify -in "$FILE"
                fi
                ;;
            dmg)
                log_info "Verifying macOS DMG..."
                log_info "Searching for signature marker '$MAC_CERT_SUBJECT' in file tail..."
                # Check the last 500kb for the certificate subject name
                if tail -c 500k "$FILE" | grep -q -a "$MAC_CERT_SUBJECT"; then
                    log_info "Signature marker found: '$MAC_CERT_SUBJECT'"
                    echo -e "${BLUE}[INFO]${NC} (Linux cannot cryptographically verify DMG integrity, but the signature block is present)"
                else
                    log_error "Signature marker '$MAC_CERT_SUBJECT' not found in the file."
                fi
                ;;
            appimage)
                if [ -f "$FILE.sig" ]; then
                    gpg --verify "$FILE.sig" "$FILE"
                else
                    log_error "Signature file ($FILE.sig) not found."
                fi
                ;;
            *)
                log_error "Unsupported extension: .$EXT"
                ;;
        esac
        ;;

    *)
        show_help
        ;;
esac
