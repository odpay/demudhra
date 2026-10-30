# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154
platform_system_backup() {
    :
}

platform_block_matches() {
    :
}

platform_system_changed() { :; }
platform_prepare() {
    :
}

mac_absent_trust_settings() {
    grep -F 'No Trust Settings were found' "$work/mac-trust.log" >/dev/null 2>&1 || return 1
    rm -f "$mac_trust_backup"
    printf '%s\n' "No pre-existing $mac_domain trust settings. There were no trust settings to restore after certificate and trust-setting deletion." \
        >"$backup_run/mac-trust-$mac_store_number.absent" || return 1
    log "No pre-existing $mac_domain trust settings. Recorded absence in $backup_run/mac-trust-$mac_store_number.absent."
}

mac_export_backup() {
    ensure_backup || return 1
    # securityd owns open keychains. Undo must reimport certificates through its API.
    if [ "${mac_undo_ready:-0}" = 0 ]; then
        cat >> "$backup_run/undo.sh" <<'UNDO_MAC'
mac_restore_certificate() (
    mac_undo_security=$1 mac_undo_store=$2 mac_undo_cert=$3 mac_undo_hash=$4
    mac_undo_work=$(mktemp -d "${TMPDIR:-/tmp}/demudhra-keychain-undo-XXXXXX") || exit 1
    trap 'rm -rf "$mac_undo_work"' 0
    "$mac_undo_security" find-certificate -a -p "$mac_undo_store" > "$mac_undo_work/export.pem" || exit 1
    awk -v dir="$mac_undo_work" '
        /-----BEGIN CERTIFICATE-----/ {n++; out=dir "/" n ".pem"; inside=1}
        inside {print > out}
        /-----END CERTIFICATE-----/ {inside=0; close(out)}
    ' "$mac_undo_work/export.pem" || exit 1
    for mac_undo_existing in "$mac_undo_work/"[0-9]*.pem; do
        [ -f "$mac_undo_existing" ] || continue
        openssl x509 -in "$mac_undo_existing" -outform DER -out "$mac_undo_work/der" || exit 1
        mac_undo_existing_hash=$(openssl dgst -sha256 "$mac_undo_work/der" | awk '{print tolower($NF)}') || exit 1
        [ "$mac_undo_existing_hash" != "$mac_undo_hash" ] || exit 0
    done
    "$mac_undo_security" add-certificates -k "$mac_undo_store" "$mac_undo_cert"
)
UNDO_MAC
        mac_undo_ready=1
    fi
    mac_store_number=$((mac_store_number + 1))
    mac_trust_backup=$backup_run/mac-trust-$mac_store_number.plist
    mac_import=
    if [ "$mac_domain" = system ]; then
        set -- -d
    else
        set --
    fi
    if "$mac_security" trust-settings-export "$@" "$mac_trust_backup" >"$work/mac-trust.log" 2>&1; then
        [ -s "$mac_trust_backup" ] || { fail "Empty trust-settings export for $mac_store. Keychain unchanged."; return 1; }
        mac_import="$(quote "$mac_security") trust-settings-import"
        [ "$mac_domain" != system ] || mac_import="$mac_import -d"
        mac_import="$mac_import $(quote "$mac_trust_backup")"
        backed=$((backed + 1))
    elif ! mac_absent_trust_settings; then
        fail "Cannot export $mac_domain trust settings before editing $mac_store. Keychain unchanged. $(cat "$work/mac-trust.log")"
        return 1
    fi
    for mac_backup_cert in "$work/mac-matches/"*.pem; do
        [ -f "$mac_backup_cert" ] || continue
        mac_backup_hash=$(fingerprint "$mac_backup_cert") || { fail 'Cannot hash keychain backup'; return 1; }
        mac_saved_cert=$backup_run/mac-$mac_store_number-$mac_backup_hash.pem
        cp -p "$mac_backup_cert" "$mac_saved_cert" || { fail 'Cannot save keychain certificate backup'; return 1; }
        backed=$((backed + 1))
        add_undo "mac_restore_certificate $(quote "$mac_security") $(quote "$mac_store") $(quote "$mac_saved_cert") $(quote "$mac_backup_hash")" || return 1
    done
    [ -z "$mac_import" ] || add_undo "$mac_import" || return 1
    mac_backup_ready=1
}

mac_split_export() {
    awk -v dir="$2" '
        /-----BEGIN CERTIFICATE-----/ {
            if (inside) {bad=1; exit 1}
            inside=1; n++; out=dir "/" n ".pem"
        }
        inside {print > out}
        /-----END CERTIFICATE-----/ {
            if (!inside) {bad=1; exit 1}
            inside=0; close(out)
        }
        END {if (inside || bad) exit 1}
    ' "$1"
}

mac_inspect_keychain() {
    mac_store=$1
    mac_domain=$2
    mac_readonly=$3
    [ -e "$mac_store" ] || return 0
    safe_path "$mac_store" || {
        fail "Unsafe keychain path $mac_store. Skipped."
        return 0
    }
    mac_store=$resolved
    mac_owner_readonly=0
    if [ "$mac_domain" = user ]; then
        # Only the numeric owner field is read; the pathname is never parsed.
        # shellcheck disable=SC2012
        mac_owner_uid=$(ls -nd "$mac_store" | awk '{print $3}')
        case $mac_owner_uid in ''|*[!0-9]*) fail "Cannot determine owning user of $mac_store"; return 0;; esac
        [ "$mac_owner_uid" = "$(id -u)" ] || mac_owner_readonly=1
    fi
    if [ "$apply" = 1 ]; then
        mac_plan=$(DEMUDHRA_LOOKUP_PATH="$mac_store" awk -F '\t' '$1==ENVIRON["DEMUDHRA_LOOKUP_PATH"] {print $2; exit}' "$work/mac-plans")
        [ -n "$mac_plan" ] || return 0
        if ! "$mac_security" find-certificate -a -p "$mac_store" > "$work/mac-current.pem" 2> "$work/mac-security.log" ||
            ! cmp -s "$work/mac-current.pem" "$work/mac-reviewed-$mac_plan"; then
            fail "Changed during scan, left unchanged: $mac_store"; return 0
        fi
        cp "$work/mac-reviewed-$mac_plan" "$work/mac-export.pem" || return 0
    else
    if ! "$mac_security" find-certificate -a -p "$mac_store" >"$work/mac-export.pem" 2>"$work/mac-security.log"; then
        fail "Cannot read keychain $mac_store. $(cat "$work/mac-security.log")"
        return 0
    fi
        mac_plan_count=$(($(wc -l < "$work/mac-plans") + 1))
        cp "$work/mac-export.pem" "$work/mac-reviewed-$mac_plan_count" || { fail "Cannot save keychain inventory: $mac_store"; return 0; }
        printf '%s\t%s\n' "$mac_store" "$mac_plan_count" >> "$work/mac-plans"
    fi
    rm -rf "$work/mac-certs"
    mkdir "$work/mac-certs" || {
        fail 'Cannot create private keychain inspection directory.'
        return 0
    }
    if ! mac_split_export "$work/mac-export.pem" "$work/mac-certs"; then
        fail "Malformed certificate export from $mac_store. Keychain unchanged."
        return 0
    fi
    rm -rf "$work/mac-matches"
    cp -R "$work/mac-certs" "$work/mac-matches" || {
        fail 'Cannot save keychain inspection inventory.'
        return 0
    }
    mac_backup_ready=0
    for mac_cert in "$work/mac-matches/"*.pem; do
        [ -f "$mac_cert" ] || continue
        if ! mac_hash=$(fingerprint "$mac_cert"); then
            fail "Cannot fingerprint a certificate exported from $mac_store."
            continue
        fi
        selected "$mac_hash" || continue
        match_place keychain "$mac_store" 1
        found=$((found + 1))
        log "FOUND keychain $mac_store SHA256=$mac_hash"
        if [ "$mac_owner_readonly" = 1 ]; then
            immutable=$((immutable + 1))
            manual_remaining=$((manual_remaining + 1))
            log "NOT REMOVED: $mac_store belongs to uid $mac_owner_uid. User trust settings must be exported and restored in that user's own session."
            mac_owner_command="sudo -u $(quote "#$mac_owner_uid") sh $(quote "${DEMUDHRA_SCRIPT_PATH:-$0}") --no-system --yes"
            [ "$all" = 0 ] || mac_owner_command="$mac_owner_command --all-emudhra"
            [ "$include_aaa" = 0 ] || mac_owner_command="$mac_owner_command --include-aaa"
            log "Manual step, from that user's logged-in and unlocked session using a saved script file: $mac_owner_command"
            continue
        fi
        if [ "$mac_readonly" = 1 ]; then
            immutable=$((immutable + 1))
            manual_remaining=$((manual_remaining + 1))
            log "NOT REMOVED. REPORT ONLY: $mac_store is a SIP-protected System root store. Its certificates are not deleted."
            log "Manual step for SHA256=$mac_hash. Install Apple security updates. The SIP root store remains OS-managed. A separately reviewed admin-domain distrust can be applied without disabling SIP."
            if [ "$apply" = 1 ]; then
                mac_manual_dir=$backup_base/manual-certificates
                mac_manual_cert=$mac_manual_dir/sip-$mac_hash.pem
                if mkdir -p "$mac_manual_dir" && mac_manual_stage=$(mktemp "$mac_manual_dir/.export-XXXXXX") &&
                    cp -p "$mac_cert" "$mac_manual_stage" && mv -f "$mac_manual_stage" "$mac_manual_cert"; then
                    log "Manual commands, only if you choose admin-domain distrust:"
                    log "  sudo security trust-settings-export -d $(quote "$mac_manual_dir/admin-before-$mac_hash.plist")"
                    log "  sudo security add-trusted-cert -d -r deny -k $(quote "$root/Library/Keychains/System.keychain") $(quote "$mac_manual_cert")"
                    log "Restore manual trust change: sudo security trust-settings-import -d $(quote "$mac_manual_dir/admin-before-$mac_hash.plist")"
                else fail 'Cannot preserve the SIP certificate for the printed manual step'; fi
            else
                log "Manual step: after confirming, use the preserved SHA-256-verified PEM with security add-trusted-cert -d -r deny. Back up admin trust settings first with security trust-settings-export -d."
            fi
            continue
        fi
        if [ "$apply" = 0 ]; then
            log "WOULD REMOVE keychain certificate SHA256=$mac_hash from $mac_store"
            continue
        fi
        can_modify "$mac_store" || continue
        if [ "$mac_backup_ready" = 0 ] && ! mac_export_backup; then
            continue
        fi
        if mac_delete_certificate; then
            if ! "$mac_security" find-certificate -a -p "$mac_store" >"$work/mac-after.pem" 2>"$work/mac-security.log"; then
                fail "Certificate delete returned success but $mac_store could not be re-read. Restore from the printed backup if needed."
                continue
            fi
            rm -rf "$work/mac-check"
            mkdir "$work/mac-check" || {
                fail 'Cannot create post-delete verification directory.'
                continue
            }
            if ! mac_split_export "$work/mac-after.pem" "$work/mac-check"; then
                fail "Malformed post-delete certificate export from $mac_store."
                continue
            fi
            mac_still_present=0
            : >"$work/mac-after-hashes"
            for mac_check in "$work/mac-check/"*.pem; do
                [ -f "$mac_check" ] || continue
                mac_check_hash=$(fingerprint "$mac_check") || {
                    mac_still_present=1
                    break
                }
                printf '%s\n' "$mac_check_hash" >>"$work/mac-after-hashes"
                [ "$mac_check_hash" != "$mac_hash" ] || mac_still_present=1
            done
            : >"$work/mac-expected-hashes"
            for mac_check in "$work/mac-certs/"*.pem; do
                [ -f "$mac_check" ] || continue
                mac_check_hash=$(fingerprint "$mac_check") || {
                    mac_still_present=1
                    break
                }
                if [ "$mac_check_hash" != "$mac_hash" ]; then
                    printf '%s\n' "$mac_check_hash" >>"$work/mac-expected-hashes"
                fi
            done
            sort "$work/mac-after-hashes" >"$work/mac-after-sorted"
            sort "$work/mac-expected-hashes" >"$work/mac-expected-sorted"
            if ! cmp -s "$work/mac-after-sorted" "$work/mac-expected-sorted"; then
                fail "Unexpected certificate set after deleting SHA256=$mac_hash from $mac_store. Restore from the printed backup."
                continue
            fi
            rm -rf "$work/mac-certs"
            mkdir "$work/mac-certs" || {
                fail 'Cannot refresh keychain certificate inventory.'
                continue
            }
            mac_split_export "$work/mac-after.pem" "$work/mac-certs" || {
                fail 'Cannot refresh keychain certificate inventory.'
                continue
            }
            if [ "$mac_still_present" = 1 ]; then
                fail "SHA256=$mac_hash remains after delete in $mac_store. Restore from backup and inspect this keychain."
            else
                removed=$((removed + 1))
                log "REMOVED keychain SHA256=$mac_hash from $mac_store"
            fi
        else
            manual_remaining=$((manual_remaining + 1))
            fail "NOT REMOVED SHA256=$mac_hash from $mac_store. The keychain may be locked or protected. Manual step: unlock this keychain in Keychain Access, verify the SHA-256 fingerprint, delete the certificate and its trust settings, then rerun. $(cat "$work/mac-delete.log")"
        fi
    done
}

mac_sha1() {
    openssl x509 -in "$1" -noout -fingerprint -sha1 2>/dev/null |
        awk -F= '{h=tolower($NF); gsub(/:/,"",h); if(length(h)!=40 || h ~ /[^0-9a-f]/) exit 1; print h}'
}

mac_delete_certificate() {
    # Older security accepts only SHA-1 for -Z. Derive that selector from a
    # SHA-256-selected certificate and refuse collisions in a fresh inventory.
    # https://raw.githubusercontent.com/apple-oss-distributions/Security/main/SecurityTool/macOS/security.c
    if "$mac_security" delete-certificate -t -Z "$mac_hash" "$mac_store" >"$work/mac-delete.log" 2>&1; then return 0; fi
    [ "$(fingerprint "$mac_cert")" = "$mac_hash" ] || return 1
    mac_sha1_hash=$(mac_sha1 "$mac_cert") || return 1
    [ -n "$mac_sha1_hash" ] || return 1
    "$mac_security" find-certificate -a -p "$mac_store" >"$work/mac-fallback.pem" 2>>"$work/mac-delete.log" || return 1
    rm -rf "$work/mac-fallback"
    mkdir "$work/mac-fallback" || return 1
    mac_split_export "$work/mac-fallback.pem" "$work/mac-fallback" || return 1
    mac_fallback_found=0
    for mac_fallback_cert in "$work/mac-fallback/"*.pem; do
        [ -f "$mac_fallback_cert" ] || continue
        mac_fallback_sha1=$(mac_sha1 "$mac_fallback_cert") || return 1
        [ "$mac_fallback_sha1" = "$mac_sha1_hash" ] || continue
        mac_fallback_sha256=$(fingerprint "$mac_fallback_cert") || return 1
        if [ "$mac_fallback_sha256" != "$mac_hash" ]; then
            log "Refusing ambiguous SHA-1 selector for SHA256=$mac_hash. Use Keychain Access after verifying the exact SHA-256 fingerprint." >&2
            return 1
        fi
        mac_fallback_found=1
    done
    [ "$mac_fallback_found" = 1 ] || return 1
    log "SHA-256 deletion failed. Retrying the older SHA-1 -Z API only for the certificate verified as SHA256=$mac_hash; removing its trust settings with -t."
    "$mac_security" delete-certificate -t -Z "$mac_sha1_hash" "$mac_store" >>"$work/mac-delete.log" 2>&1
}

mac_user_paths() {
    for mac_login in "$1/Library/Keychains/login.keychain" "$1/Library/Keychains/login.keychain-db"; do
        [ -f "$mac_login" ] || continue
        plain_path "$mac_login" || { fail 'Unrepresentable login keychain path'; continue; }
        grep -F -x -q "$mac_login" "$work/mac-login-paths" || printf '%s\n' "$mac_login" >>"$work/mac-login-paths"
    done
}

mac_firefox_home() {
    for mac_profile in "$1/Library/Application Support/Firefox/Profiles/"*; do
        [ -d "$mac_profile" ] || continue
        for mac_nss in "$mac_profile/cert9.db" "$mac_profile/cert8.db"; do
            [ -f "$mac_nss" ] || continue
            process_path "$mac_nss"
        done
    done
}

mac_discover_firefox() {
    [ "$skip_nss" = 0 ] || return 0
    for mac_home in "$root/Users/"*; do
        [ -d "$mac_home" ] || continue
        mac_firefox_home "$mac_home"
    done
    if [ -n "${HOME-}" ]; then
        if [ -z "$root" ]; then mac_firefox_home "$HOME"
        else case $HOME in "$root"/*) mac_firefox_home "$HOME";; esac; fi
    fi
}

platform_main() {
    if [ "$skip_system" = 0 ] && [ -f "$root/etc/ssl/cert.pem" ]; then
        if safe_path "$root/etc/ssl/cert.pem"; then
            # Apple supports administrator edits here, unlike the SIP root keychain.
            # https://support.apple.com/en-us/149555 (published 2026-10-29).
            ecosystem=system
            inspect_bundle "$resolved"
            if [ "$apply" = 0 ]; then
                log 'Safari, Mail and system apps are already protected by Apple. This run fixes command-line tools using /etc/ssl/cert.pem.'
                log 'A macOS update may restore /etc/ssl/cert.pem. Rerun demudhra after updating.'
                if [ "$include_aaa" = 0 ] && [ -s "$work/ranges" ] &&
                    awk -F '\t' '$2=="opt-in-cross-sign" {print tolower($1)}' "$table" > "$work/mac-aaa" &&
                    awk 'NR==FNR {aaa[$1]=1; next} tolower($NF) in aaa {found=1} END {exit !found}' "$work/mac-aaa" "$work/hashes"; then
                    log 'The 6 Sectigo cross-signed intermediates still verify via AAA in this file; --include-aaa optionally removes it, but may break sites chained through unaffected Sectigo intermediates.'
                fi
            fi
        else
            fail 'Cannot safely inspect macOS /etc/ssl/cert.pem.'
        fi
    fi
    mac_discover_firefox
    if [ "$skip_keychains" = 1 ]; then
        log 'SKIP macOS keychains (--no-keychains).'
        return 0
    fi
    mac_security=
    # DEMUDHRA_TEST_ONLY_BEGIN
    if [ -n "$root" ] && [ "${DEMUDHRA_TESTING:-}" = 1 ]; then
        case ${DEMUDHRA_TEST_SECURITY-} in
            /*) mac_security=$DEMUDHRA_TEST_SECURITY ;;
            *)
                immutable=$((immutable + 1))
                log 'TEST ROOT: keychain commands disabled. Set DEMUDHRA_TEST_SECURITY to an absolute test shim to exercise them.'
                return 0
                ;;
        esac
        [ -x "$mac_security" ] || {
            fail 'DEMUDHRA_TEST_SECURITY is not executable. No keychains inspected.'
            return 0
        }
        log "WARNING: TEST-ONLY security shim active: $mac_security"
    fi
    # DEMUDHRA_TEST_ONLY_END
    if [ -z "$mac_security" ] && command -v security >/dev/null 2>&1; then
        mac_security=security
    elif [ -z "$mac_security" ]; then
        immutable=$((immutable + 1))
        log 'Cannot inspect macOS keychains: security is unavailable.'
        return 0
    fi
    mac_store_number=0
    if [ "$skip_system" = 0 ]; then
        mac_inspect_keychain "$root/System/Library/Keychains/SystemRootCertificates.keychain" system 1
        mac_inspect_keychain "$root/Library/Keychains/System.keychain" system 0
    fi
    : >"$work/mac-login-paths"
    for mac_home in "$root/Users/"*; do
        [ -d "$mac_home" ] || continue
        mac_user_paths "$mac_home"
    done
    if [ -n "${HOME-}" ]; then
        if [ -z "$root" ]; then mac_user_paths "$HOME"
        else case $HOME in "$root"/*) mac_user_paths "$HOME";; esac; fi
    fi
    while IFS= read -r mac_login; do
        mac_inspect_keychain "$mac_login" user 0
    done <"$work/mac-login-paths"
}
