#!/usr/bin/env bash
set -euo pipefail

# ============================================================================
#  gpg-go  --  Full-Feature Integration Test Suite
# ============================================================================
#  Run:  chmod +x test.sh && ./test.sh [--verbose] [--no-color] [--filter PAT]
# ============================================================================

# --------------- configuration ---------------
BIN="./gpg-go"
HOMEDIR=""
VERBOSE=false
USE_COLOR=true
FILTER=""
FAIL=0
PASS_COUNT=0
SKIP_COUNT=0
TOTAL=0
SECTION=""
SECTION_PASS=0
SECTION_FAIL=0
SECTION_SKIP=0
SECTION_TOTAL=0
TIMINGS=()
START_TIME=$(date +%s)
LAST_OUTPUT=""

for arg in "$@"; do
    case "$arg" in
        --verbose|-v)  VERBOSE=true ;;
        --no-color)    USE_COLOR=false ;;
        --filter=*)    FILTER="${arg#--filter=}" ;;
        --filter)      shift; FILTER="$1" ;;
        --help|-h)
            echo "Usage: $0 [--verbose] [--no-color] [--filter=PATTERN]"
            echo ""
            echo "  --verbose    Show command output on failure"
            echo "  --no-color   Disable ANSI colors"
            echo "  --filter=X   Only run tests matching pattern X"
            exit 0
            ;;
    esac
done

# --------------- colors & glyphs ---------------
if $USE_COLOR && [ -t 1 ]; then
    R='\033[0m'       # reset
    BLD='\033[1m'     # bold
    DIM='\033[2m'     # dim
    GRN='\033[32m'    # green
    RED='\033[31m'    # red
    YLW='\033[33m'    # yellow
    CYN='\033[36m'    # cyan
    MAG='\033[35m'    # magenta
    WHT='\033[97m'    # white
    BG_GRN='\033[42;97m'
    BG_RED='\033[41;97m'
    BG_YLW='\033[43;30m'
    UL='\033[4m'      # underline
    SYM_PASS="+"
    SYM_FAIL="x"
    SYM_SKIP="-"
else
    R='' BLD='' DIM='' GRN='' RED='' YLW='' CYN='' MAG='' WHT=''
    BG_GRN='' BG_RED='' BG_YLW='' UL=''
    SYM_PASS="+" SYM_FAIL="x" SYM_SKIP="-"
fi

# --------------- drawing helpers ---------------
TERM_WIDTH=${COLUMNS:-$(tput cols 2>/dev/null || echo 80)}
[ "$TERM_WIDTH" -gt 120 ] && TERM_WIDTH=120

hr() {
    local char="${1:--}" label="${2:-}"
    local line=""
    if [ -n "$label" ]; then
        local pad=$(( (TERM_WIDTH - ${#label} - 4) / 2 ))
        [ "$pad" -lt 1 ] && pad=1
        printf -v line '%*s' "$pad" ''; line="${line// /$char}"
        printf "${DIM}%s${R} ${BLD}%s${R} ${DIM}%s${R}\n" "$line" "$label" "$line"
    else
        printf -v line '%*s' "$TERM_WIDTH" ''; line="${line// /$char}"
        printf "${DIM}%s${R}\n" "$line"
    fi
}

banner() {
    echo ""
    hr "=" ""
    printf "${BLD}${CYN}"
    cat << 'ART'

    ┌──────────────────────────────────┐
    │   ╔═╗┌─┐┌─┐   ╔═╗┌─┐           │
    │   ║ ╦├─┘│ ┬───║ ╦│ │           │
    │   ╚═╝┴  └─┘   ╚═╝└─┘           │
    │      Integration Test Suite      │
    └──────────────────────────────────┘
ART
    printf "${R}"
    printf "    ${DIM}version: ${R}${WHT}$($BIN --version 2>&1 | head -1)${R}\n"
    printf "    ${DIM}binary:  ${R}${WHT}$(file -b "$BIN" 2>/dev/null | cut -d, -f1-2)${R}\n"
    printf "    ${DIM}date:    ${R}${WHT}$(date '+%Y-%m-%d %H:%M:%S %Z')${R}\n"
    printf "    ${DIM}host:    ${R}${WHT}$(uname -srm)${R}\n"
    hr "=" ""
    echo ""
}

# --------------- test framework ---------------
cleanup() {
    [ -n "$HOMEDIR" ] && rm -rf "$HOMEDIR"
}
trap cleanup EXIT

gen_key() {
    echo "" | $BIN generate --homedir "$HOMEDIR" --quick --name "$1" --email "$2" --algo "${3:-ed25519}" >/dev/null 2>&1
}

get_fp() {
    $BIN fingerprint --homedir "$HOMEDIR" "$1" 2>/dev/null \
        | grep "Fingerprint:" | sed 's/.*Fingerprint: //;s/ //g'
}

section() {
    # close previous section
    if [ -n "$SECTION" ]; then
        _section_footer
    fi
    SECTION="$1"
    SECTION_PASS=0; SECTION_FAIL=0; SECTION_SKIP=0; SECTION_TOTAL=0
    echo ""
    printf "  ${BLD}${MAG}%s${R}\n" "$SECTION"
    printf "  ${DIM}"
    printf '%*s' "${#SECTION}" '' | tr ' ' '─'
    printf "${R}\n"
}

_section_footer() {
    local mark="${GRN}${SYM_PASS}${R}"
    [ "$SECTION_FAIL" -gt 0 ] && mark="${RED}${SYM_FAIL}${R}"
    printf "  ${DIM}└─ %b %d/%d passed" "$mark" "$SECTION_PASS" "$SECTION_TOTAL"
    [ "$SECTION_SKIP" -gt 0 ] && printf ", %d skipped" "$SECTION_SKIP"
    [ "$SECTION_FAIL" -gt 0 ] && printf ", ${RED}%d failed${R}" "$SECTION_FAIL"
    printf "${R}\n"
}

_should_skip() {
    if [ -n "$FILTER" ]; then
        echo "$1" | grep -qi "$FILTER" && return 1
        return 0
    fi
    return 1
}

_record() {
    local status="$1" desc="$2"
    TOTAL=$((TOTAL + 1))
    SECTION_TOTAL=$((SECTION_TOTAL + 1))
    case "$status" in
        pass)
            PASS_COUNT=$((PASS_COUNT + 1))
            SECTION_PASS=$((SECTION_PASS + 1))
            printf "    ${GRN}${SYM_PASS}${R}  %s\n" "$desc"
            ;;
        fail)
            FAIL=$((FAIL + 1))
            SECTION_FAIL=$((SECTION_FAIL + 1))
            printf "    ${RED}${SYM_FAIL}${R}  %s\n" "$desc"
            if $VERBOSE && [ -n "$LAST_OUTPUT" ]; then
                printf "       ${DIM}%s${R}\n" "$(echo "$LAST_OUTPUT" | head -5 | sed 's/^/       /')"
            fi
            ;;
        skip)
            SKIP_COUNT=$((SKIP_COUNT + 1))
            SECTION_SKIP=$((SECTION_SKIP + 1))
            printf "    ${YLW}${SYM_SKIP}${R}  ${DIM}%s (skipped)${R}\n" "$desc"
            ;;
    esac
}

run() {
    local desc="$1"; shift
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    LAST_OUTPUT=""
    if LAST_OUTPUT=$("$@" 2>&1); then
        _record pass "$desc"
    else
        _record fail "$desc"
    fi
}

run_stdin() {
    local desc="$1" input="$2"; shift 2
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    LAST_OUTPUT=""
    if LAST_OUTPUT=$(echo "$input" | "$@" 2>&1); then
        _record pass "$desc"
    else
        _record fail "$desc"
    fi
}

run_expect_fail() {
    local desc="$1"; shift
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    LAST_OUTPUT=""
    if LAST_OUTPUT=$("$@" 2>&1); then
        LAST_OUTPUT="(expected failure, but command succeeded)"
        _record fail "$desc"
    else
        _record pass "$desc"
    fi
}

run_output() {
    local desc="$1" pattern="$2"; shift 2
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    LAST_OUTPUT=""
    LAST_OUTPUT=$("$@" 2>&1) || true
    if echo "$LAST_OUTPUT" | grep -qi "$pattern"; then
        _record pass "$desc"
    else
        LAST_OUTPUT="pattern '$pattern' not found in output:\n$LAST_OUTPUT"
        _record fail "$desc"
    fi
}

run_compare() {
    local desc="$1" file_a="$2" file_b="$3"
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    LAST_OUTPUT=""
    if diff -q "$file_a" "$file_b" >/dev/null 2>&1; then
        _record pass "$desc"
    else
        LAST_OUTPUT="files differ: $file_a vs $file_b"
        _record fail "$desc"
    fi
}

run_file_exists() {
    local desc="$1" path="$2"
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    if [ -f "$path" ] && [ -s "$path" ]; then
        _record pass "$desc"
    else
        LAST_OUTPUT="file missing or empty: $path"
        _record fail "$desc"
    fi
}

run_count_gte() {
    local desc="$1" actual="$2" expected="$3"
    if _should_skip "$desc"; then _record skip "$desc"; return; fi
    if [ "$actual" -ge "$expected" ]; then
        _record pass "$desc ($actual >= $expected)"
    else
        LAST_OUTPUT="expected >= $expected, got $actual"
        _record fail "$desc"
    fi
}

FLAGS="--homedir \$HOMEDIR"  # placeholder, we set HOMEDIR below

# ============================================================================
#  SETUP
# ============================================================================
HOMEDIR=$(mktemp -d)
FLAGS="--homedir $HOMEDIR"

banner

printf "  ${DIM}Test home: ${WHT}%s${R}\n" "$HOMEDIR"
echo ""

# ============================================================================
#  1. KEY GENERATION -- multiple algorithms
# ============================================================================
section "Key Generation"

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if gen_key "Alice Crypto" "alice@example.org" ed25519; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  generate Ed25519 key (Alice)\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  generate Ed25519 key (Alice)\n"
fi

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if gen_key "Bob Secure" "bob@example.org" ed25519; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  generate Ed25519 key (Bob)\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  generate Ed25519 key (Bob)\n"
fi

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if gen_key "Carol RSA" "carol@example.org" rsa4096; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  generate RSA-4096 key (Carol)\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  generate RSA-4096 key (Carol)\n"
fi

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if gen_key "Dave Small" "dave@example.org" rsa2048; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  generate RSA-2048 key (Dave)\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  generate RSA-2048 key (Dave)\n"
fi

# ============================================================================
#  2. KEY LISTING & FINGERPRINTS
# ============================================================================
section "Key Listing & Fingerprints"

run_output "list-keys shows all 4 keys" "Alice Crypto" \
    $BIN list-keys $FLAGS
run_output "list-keys shows Bob" "Bob Secure" \
    $BIN list-keys $FLAGS
run_output "list-keys shows Carol (RSA)" "Carol RSA" \
    $BIN list-keys $FLAGS
run_output "list-keys shows Dave" "Dave Small" \
    $BIN list-keys $FLAGS
run_output "list-secret-keys works" "alice@example.org" \
    $BIN list-secret-keys $FLAGS

ALICE_FP=$(get_fp "Alice Crypto")
BOB_FP=$(get_fp "Bob Secure")
CAROL_FP=$(get_fp "Carol RSA")
DAVE_FP=$(get_fp "Dave Small")

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if [ -n "$ALICE_FP" ] && [ ${#ALICE_FP} -eq 40 ]; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  Alice fingerprint is 40-char hex\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  Alice fingerprint extraction failed\n"
fi

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if [ -n "$CAROL_FP" ] && [ ${#CAROL_FP} -eq 40 ]; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  Carol (RSA) fingerprint is 40-char hex\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  Carol (RSA) fingerprint extraction failed\n"
fi

run_output "list-keys shows subkey lines" "sub:" \
    $BIN list-keys $FLAGS

run_output "fingerprint cmd shows formatted FP" "Fingerprint:" \
    $BIN fingerprint $FLAGS "Alice Crypto"

# ============================================================================
#  3. ENCRYPTION / DECRYPTION  --  Ed25519
# ============================================================================
section "Encrypt / Decrypt (Ed25519)"

echo "The quick brown fox jumps over the lazy dog." > "$HOMEDIR/plain.txt"

# Armored
run "encrypt armored for Alice" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/enc_alice.asc" -r "Alice Crypto" "$HOMEDIR/plain.txt"
run_output "output contains PGP header" "BEGIN PGP MESSAGE" \
    cat "$HOMEDIR/enc_alice.asc"
run "decrypt armored" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec_alice.txt" "$HOMEDIR/enc_alice.asc"
run_compare "decrypted matches original" "$HOMEDIR/plain.txt" "$HOMEDIR/dec_alice.txt"

# Binary
run "encrypt binary for Alice" \
    $BIN encrypt $FLAGS -o "$HOMEDIR/enc_alice.gpg" -r "Alice Crypto" "$HOMEDIR/plain.txt"
run "decrypt binary" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec_alice_bin.txt" "$HOMEDIR/enc_alice.gpg"
run_compare "binary decrypt matches original" "$HOMEDIR/plain.txt" "$HOMEDIR/dec_alice_bin.txt"

# Multi-recipient
run "encrypt for Alice + Bob" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/enc_multi.asc" -r "Alice Crypto" -r "Bob Secure" "$HOMEDIR/plain.txt"
run "decrypt multi-recipient" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec_multi.txt" "$HOMEDIR/enc_multi.asc"
run_compare "multi-recipient decrypt matches" "$HOMEDIR/plain.txt" "$HOMEDIR/dec_multi.txt"

# Stdin piping
run_output "encrypt via stdin pipe" "BEGIN PGP MESSAGE" \
    bash -c "echo 'piped message' | $BIN encrypt $FLAGS -a -r 'Alice Crypto'"

# ============================================================================
#  4. ENCRYPTION / DECRYPTION  --  RSA
# ============================================================================
section "Encrypt / Decrypt (RSA-4096)"

run "encrypt armored for Carol (RSA)" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/enc_carol.asc" -r "Carol RSA" "$HOMEDIR/plain.txt"
run "decrypt Carol's message" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec_carol.txt" "$HOMEDIR/enc_carol.asc"
run_compare "RSA decrypt matches original" "$HOMEDIR/plain.txt" "$HOMEDIR/dec_carol.txt"

# Cross-algorithm multi-recipient
run "encrypt for Ed25519 + RSA recipients" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/enc_cross.asc" -r "Alice Crypto" -r "Carol RSA" "$HOMEDIR/plain.txt"
run "decrypt cross-algo message" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/dec_cross.txt" "$HOMEDIR/enc_cross.asc"
run_compare "cross-algo decrypt matches" "$HOMEDIR/plain.txt" "$HOMEDIR/dec_cross.txt"

# ============================================================================
#  5. SYMMETRIC ENCRYPTION
# ============================================================================
section "Symmetric Encryption"

run_output "symmetric encrypt (armored)" "BEGIN PGP MESSAGE" \
    bash -c "echo 'symmetric secret' | echo 'testpass' | $BIN encrypt $FLAGS -c -a 2>&1 || true"

# ============================================================================
#  6. SIGNING -- detached, inline, clearsign
# ============================================================================
section "Digital Signatures (Ed25519)"

# Detached armored
run "create detached sig (armored)" \
    $BIN sign $FLAGS -a --detach-sign -o "$HOMEDIR/det.asc" -u "Alice Crypto" "$HOMEDIR/plain.txt"
run_output "detached sig has PGP header" "BEGIN PGP SIGNATURE" \
    cat "$HOMEDIR/det.asc"
run "verify detached sig" \
    $BIN verify $FLAGS "$HOMEDIR/det.asc" "$HOMEDIR/plain.txt"

# Detached binary
run "create detached sig (binary)" \
    $BIN sign $FLAGS --detach-sign -o "$HOMEDIR/det.sig" -u "Alice Crypto" "$HOMEDIR/plain.txt"
run "verify binary detached sig" \
    $BIN verify $FLAGS "$HOMEDIR/det.sig" "$HOMEDIR/plain.txt"

# Inline
run "create inline signature" \
    $BIN sign $FLAGS -a -o "$HOMEDIR/inline.asc" -u "Alice Crypto" "$HOMEDIR/plain.txt"
run "verify inline signature" \
    $BIN verify $FLAGS "$HOMEDIR/inline.asc"

# Clearsign
run "create clearsign signature" \
    $BIN sign $FLAGS --clear-sign -o "$HOMEDIR/clear.asc" -u "Alice Crypto" "$HOMEDIR/plain.txt"
run_output "clearsign has SIGNED MESSAGE header" "BEGIN PGP SIGNED MESSAGE" \
    cat "$HOMEDIR/clear.asc"
run_output "clearsign body contains original text" "quick brown fox" \
    cat "$HOMEDIR/clear.asc"
run "verify clearsign" \
    $BIN verify $FLAGS "$HOMEDIR/clear.asc"

# Signing with Bob's key
run "sign with Bob's key" \
    $BIN sign $FLAGS -a --detach-sign -o "$HOMEDIR/bob.sig" -u "Bob Secure" "$HOMEDIR/plain.txt"
run "verify Bob's signature" \
    $BIN verify $FLAGS "$HOMEDIR/bob.sig" "$HOMEDIR/plain.txt"

# ============================================================================
#  7. SIGNING -- RSA
# ============================================================================
section "Digital Signatures (RSA)"

run "sign with Carol (RSA-4096)" \
    $BIN sign $FLAGS -a --detach-sign -o "$HOMEDIR/carol.sig" -u "Carol RSA" "$HOMEDIR/plain.txt"
run "verify Carol's RSA signature" \
    $BIN verify $FLAGS "$HOMEDIR/carol.sig" "$HOMEDIR/plain.txt"

run "RSA clearsign" \
    $BIN sign $FLAGS --clear-sign -o "$HOMEDIR/carol_clear.asc" -u "Carol RSA" "$HOMEDIR/plain.txt"
run "verify RSA clearsign" \
    $BIN verify $FLAGS "$HOMEDIR/carol_clear.asc"

# ============================================================================
#  8. SIGNATURE INTEGRITY
# ============================================================================
section "Signature Integrity & Tamper Detection"

cp "$HOMEDIR/plain.txt" "$HOMEDIR/tampered.txt"
echo "INJECTED MALICIOUS CONTENT" >> "$HOMEDIR/tampered.txt"

run_expect_fail "reject tampered file (Ed25519)" \
    $BIN verify $FLAGS "$HOMEDIR/det.asc" "$HOMEDIR/tampered.txt"
run_expect_fail "reject tampered file (RSA)" \
    $BIN verify $FLAGS "$HOMEDIR/carol.sig" "$HOMEDIR/tampered.txt"

echo "totally bogus signature" > "$HOMEDIR/bogus.sig"
run_expect_fail "reject bogus signature file" \
    $BIN verify $FLAGS "$HOMEDIR/bogus.sig" "$HOMEDIR/plain.txt"

# ============================================================================
#  9. EXPORT / IMPORT / DELETE
# ============================================================================
section "Export / Import / Delete Lifecycle"

# Export public
run "export Alice public key (armored)" \
    $BIN export $FLAGS -a -o "$HOMEDIR/alice.pub" "Alice Crypto"
run_output "exported key has PGP header" "BEGIN PGP PUBLIC KEY" \
    cat "$HOMEDIR/alice.pub"
run_file_exists "exported file is non-empty" "$HOMEDIR/alice.pub"

# Export secret
run "export Alice secret key" \
    $BIN export $FLAGS -a --secret -o "$HOMEDIR/alice.sec" "Alice Crypto"
run_output "secret key has PRIVATE KEY header" "BEGIN PGP PRIVATE KEY" \
    cat "$HOMEDIR/alice.sec"

# Export Bob too
run "export Bob public key" \
    $BIN export $FLAGS -a -o "$HOMEDIR/bob.pub" "Bob Secure"

# Delete + reimport
run "delete Alice (public + secret)" \
    $BIN delete $FLAGS --secret "$ALICE_FP"
run_expect_fail "Alice is gone after delete" \
    $BIN fingerprint $FLAGS "Alice Crypto"

run "reimport Alice public key" \
    $BIN import $FLAGS "$HOMEDIR/alice.pub"
run_output "Alice reappears in list" "Alice Crypto" \
    $BIN list-keys $FLAGS

# Delete Bob + reimport
run "delete Bob" \
    $BIN delete $FLAGS --secret "$BOB_FP"
run_expect_fail "Bob is gone" \
    $BIN fingerprint $FLAGS "Bob Secure"
run "reimport Bob" \
    $BIN import $FLAGS "$HOMEDIR/bob.pub"
run_output "Bob is back" "Bob Secure" \
    $BIN list-keys $FLAGS

# ============================================================================
#  10. ADD SUBKEY
# ============================================================================
section "Subkey Management"

TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if gen_key "Keyholder" "keys@example.org" ed25519; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  generate fresh key for subkey tests\n"
else
    FAIL=$((FAIL + 1)); SECTION_FAIL=$((SECTION_FAIL + 1))
    printf "    ${RED}${SYM_FAIL}${R}  generate fresh key for subkey tests\n"
fi
KH_FP=$(get_fp "Keyholder")

INITIAL_SUBS=$($BIN list-keys $FLAGS 2>/dev/null | grep -c "sub:" || true)

run "add encryption subkey" \
    $BIN add-subkey $FLAGS "$KH_FP" --type encrypt
run "add signing subkey" \
    $BIN add-subkey $FLAGS "$KH_FP" --type sign

NEW_SUBS=$($BIN list-keys $FLAGS 2>/dev/null | grep -c "sub:" || true)
run_count_gte "subkey count increased" "$NEW_SUBS" "$((INITIAL_SUBS + 2))"

run_output "list shows [encrypt] subkey" "encrypt" \
    $BIN list-keys $FLAGS
run_output "list shows [sign] subkey" "sign" \
    $BIN list-keys $FLAGS

# Verify encrypt/decrypt still works after adding subkeys
echo "post-rotation payload" > "$HOMEDIR/rotate.txt"
run "encrypt after subkey addition" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/rotate.asc" -r "Keyholder" "$HOMEDIR/rotate.txt"
run "decrypt after subkey addition" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/rotate_dec.txt" "$HOMEDIR/rotate.asc"
run_compare "subkey rotation roundtrip" "$HOMEDIR/rotate.txt" "$HOMEDIR/rotate_dec.txt"

# Add subkey with expiration
run "add encrypt subkey with expiry" \
    $BIN add-subkey $FLAGS "$KH_FP" --type encrypt --expire 8760h

# ============================================================================
#  11. ADD UID
# ============================================================================
section "UID Management"

run "add alternate UID" \
    $BIN add-uid $FLAGS "$KH_FP" --name "Keyholder Alt" --email "alt@example.org"
run_output "new UID in listing" "alt@example.org" \
    $BIN list-keys $FLAGS

run "add UID with comment" \
    $BIN add-uid $FLAGS "$KH_FP" --name "Keyholder Work" --email "work@example.org" --comment "office key"
run_output "commented UID in listing" "work@example.org" \
    $BIN list-keys $FLAGS

# Verify key still works with multiple UIDs
echo "multi-uid test" > "$HOMEDIR/uid_test.txt"
run "encrypt to multi-UID key" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/uid_enc.asc" -r "Keyholder" "$HOMEDIR/uid_test.txt"
run "decrypt from multi-UID key" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/uid_dec.txt" "$HOMEDIR/uid_enc.asc"
run_compare "multi-UID roundtrip" "$HOMEDIR/uid_test.txt" "$HOMEDIR/uid_dec.txt"

# ============================================================================
#  12. TRUST DATABASE
# ============================================================================
section "Trust Database"

run "set trust to full" \
    $BIN edit-trust $FLAGS "$KH_FP" full
run_output "trust listing shows Keyholder" "Keyholder" \
    $BIN list-trust $FLAGS
run "set trust to marginal" \
    $BIN edit-trust $FLAGS "$KH_FP" marginal
run "set trust to ultimate" \
    $BIN edit-trust $FLAGS "$KH_FP" ultimate

# ============================================================================
#  13. REVOCATION CERTIFICATE
# ============================================================================
section "Revocation Certificate"

run "generate revocation cert" \
    $BIN gen-revoke $FLAGS -o "$HOMEDIR/revoke.asc" "$KH_FP"
run_file_exists "revocation cert file exists" "$HOMEDIR/revoke.asc"
run_output "revocation cert has PGP header" "BEGIN PGP PUBLIC KEY" \
    cat "$HOMEDIR/revoke.asc"

# ============================================================================
#  14. JSON OUTPUT
# ============================================================================
section "JSON / Machine-Readable Output"

run_output "list-keys --json has key_id" '"key_id"' \
    $BIN list-keys $FLAGS --json
run_output "list-keys --json has fingerprint" '"fingerprint"' \
    $BIN list-keys $FLAGS --json
run_output "list-secret-keys --json works" '"key_id"' \
    $BIN list-secret-keys $FLAGS --json

# Validate it's actual JSON
TOTAL=$((TOTAL + 1)); SECTION_TOTAL=$((SECTION_TOTAL + 1))
if $BIN list-keys $FLAGS --json 2>/dev/null | python3 -m json.tool >/dev/null 2>&1; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  JSON output is valid (python3 json.tool)\n"
elif $BIN list-keys $FLAGS --json 2>/dev/null | jq . >/dev/null 2>&1; then
    PASS_COUNT=$((PASS_COUNT + 1)); SECTION_PASS=$((SECTION_PASS + 1))
    printf "    ${GRN}${SYM_PASS}${R}  JSON output is valid (jq)\n"
else
    # skip if no json validator available
    SKIP_COUNT=$((SKIP_COUNT + 1)); SECTION_SKIP=$((SECTION_SKIP + 1))
    printf "    ${YLW}${SYM_SKIP}${R}  ${DIM}JSON validation skipped (no python3/jq)${R}\n"
fi

# ============================================================================
#  15. AUDIT
# ============================================================================
section "Security Audit"

run_output "audit command runs" "audit" \
    $BIN audit $FLAGS
run_output "audit mentions key count" "keys" \
    $BIN audit $FLAGS

# ============================================================================
#  16. AGENT
# ============================================================================
section "Agent (Passphrase Cache)"

run_output "agent status (not running)" "not running" \
    $BIN agent status $FLAGS

# ============================================================================
#  17. GIT INTEGRATION
# ============================================================================
section "Git Integration"

run_output "git status shows config" "gpg.program" \
    $BIN git status $FLAGS

# ============================================================================
#  18. LARGE PAYLOAD
# ============================================================================
section "Stress: Large Payload"

dd if=/dev/urandom bs=1024 count=512 of="$HOMEDIR/big.bin" 2>/dev/null
run "encrypt 512KB binary" \
    $BIN encrypt $FLAGS -o "$HOMEDIR/big.gpg" -r "Keyholder" "$HOMEDIR/big.bin"
run "decrypt 512KB binary" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/big_dec.bin" "$HOMEDIR/big.gpg"
run_compare "large file roundtrip matches" "$HOMEDIR/big.bin" "$HOMEDIR/big_dec.bin"

# Sign large file
run "sign large file (detached)" \
    $BIN sign $FLAGS --detach-sign -o "$HOMEDIR/big.sig" -u "Keyholder" "$HOMEDIR/big.bin"
run "verify large file signature" \
    $BIN verify $FLAGS "$HOMEDIR/big.sig" "$HOMEDIR/big.bin"

# ============================================================================
#  19. EMPTY / EDGE CASES
# ============================================================================
section "Edge Cases & Error Handling"

# Empty file
touch "$HOMEDIR/empty.txt"
run "encrypt empty file" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/empty.asc" -r "Keyholder" "$HOMEDIR/empty.txt"
run "decrypt empty file" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/empty_dec.txt" "$HOMEDIR/empty.asc"

# Unicode content
printf 'Sch\xc3\xb6ne Gr\xc3\xbc\xc3\x9fe! \xe2\x9c\x93 \xf0\x9f\x94\x91\n' > "$HOMEDIR/unicode.txt"
run "encrypt unicode content" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/unicode.asc" -r "Keyholder" "$HOMEDIR/unicode.txt"
run "decrypt unicode content" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/unicode_dec.txt" "$HOMEDIR/unicode.asc"
run_compare "unicode roundtrip matches" "$HOMEDIR/unicode.txt" "$HOMEDIR/unicode_dec.txt"

# Newlines-only file
printf '\n\n\n\n\n' > "$HOMEDIR/newlines.txt"
run "encrypt newlines-only file" \
    $BIN encrypt $FLAGS -a -o "$HOMEDIR/newlines.asc" -r "Keyholder" "$HOMEDIR/newlines.txt"
run "decrypt newlines-only file" \
    $BIN decrypt $FLAGS -o "$HOMEDIR/newlines_dec.txt" "$HOMEDIR/newlines.asc"
run_compare "newlines roundtrip matches" "$HOMEDIR/newlines.txt" "$HOMEDIR/newlines_dec.txt"

# Error paths
run_expect_fail "encrypt to nonexistent recipient" \
    $BIN encrypt $FLAGS -r "ghost@void" "$HOMEDIR/plain.txt"
run_expect_fail "decrypt garbage data" \
    bash -c "echo 'not encrypted at all' | $BIN decrypt $FLAGS"
run_expect_fail "verify garbage data" \
    bash -c "echo 'not signed' | $BIN verify $FLAGS"
run_expect_fail "delete nonexistent key" \
    $BIN delete $FLAGS "0000000000000000000000000000000000000000"
run_expect_fail "add-subkey to missing key" \
    $BIN add-subkey $FLAGS "0000000000000000000000000000000000000000" --type encrypt
run_expect_fail "add-uid to missing key" \
    $BIN add-uid $FLAGS "0000000000000000000000000000000000000000" --name "X" --email "x@x"

# ============================================================================
#  20. CLI UX
# ============================================================================
section "CLI Help & UX"

run_output "--help shows available commands" "Available Commands" \
    $BIN --help
run_output "--version shows version" "gpg-go version" \
    $BIN --version
run_output "encrypt --help shows usage" "Usage:" \
    $BIN encrypt --help
run_output "generate --help shows --algo" "algo" \
    $BIN generate --help
run_output "sign --help shows --detach-sign" "detach-sign" \
    $BIN sign --help
run_expect_fail "unknown command fails" \
    $BIN nonexistent-command

# ============================================================================
#  RESULTS
# ============================================================================

# Close last section
_section_footer

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))

echo ""
hr "=" ""
echo ""

# Summary box
if [ "$FAIL" -eq 0 ]; then
    printf "  ${BG_GRN} ALL TESTS PASSED ${R}\n\n"
else
    printf "  ${BG_RED} SOME TESTS FAILED ${R}\n\n"
fi

# Stats table
printf "  ${BLD}%-14s${R} ${GRN}%d${R}\n"  "Passed:" "$PASS_COUNT"
[ "$FAIL" -gt 0 ] && printf "  ${BLD}%-14s${R} ${RED}%d${R}\n" "Failed:" "$FAIL"
[ "$SKIP_COUNT" -gt 0 ] && printf "  ${BLD}%-14s${R} ${YLW}%d${R}\n" "Skipped:" "$SKIP_COUNT"
printf "  ${BLD}%-14s${R} %d\n" "Total:" "$TOTAL"
printf "  ${BLD}%-14s${R} %ds\n" "Duration:" "$ELAPSED"
printf "  ${BLD}%-14s${R} %s\n" "Pass rate:" "$(awk "BEGIN{printf \"%.1f%%\", ($PASS_COUNT/$TOTAL)*100}")"

echo ""

# Progress bar
BAR_WIDTH=$((TERM_WIDTH - 10))
if [ "$TOTAL" -gt 0 ]; then
    PASS_W=$(( (PASS_COUNT * BAR_WIDTH) / TOTAL ))
    FAIL_W=$(( (FAIL * BAR_WIDTH) / TOTAL ))
    SKIP_W=$(( (SKIP_COUNT * BAR_WIDTH) / TOTAL ))
    # Fill remainder with pass if rounding left gaps
    REMAINDER=$(( BAR_WIDTH - PASS_W - FAIL_W - SKIP_W ))
    [ "$FAIL" -eq 0 ] && PASS_W=$((PASS_W + REMAINDER)) || FAIL_W=$((FAIL_W + REMAINDER))

    printf "  ${DIM}[${R}"
    printf "${BG_GRN}%*s${R}" "$PASS_W" ""
    [ "$FAIL_W" -gt 0 ] && printf "${BG_RED}%*s${R}" "$FAIL_W" ""
    [ "$SKIP_W" -gt 0 ] && printf "${BG_YLW}%*s${R}" "$SKIP_W" ""
    printf "${DIM}]${R}\n"
fi

echo ""
hr "=" ""
echo ""

if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
