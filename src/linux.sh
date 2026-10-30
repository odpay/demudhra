# shellcheck shell=sh
# shellcheck disable=SC2034,SC2154
restore_system_bytes() {
    preserve_index=1
    while [ "$preserve_index" -le "$preserve_count" ]; do
        preserve_path=$(cat "$work/preserve-$preserve_index.path")
        preserve_bytes=$work/preserve-$preserve_index.bytes
        if [ -f "$preserve_path" ] && ! cmp -s "$preserve_path" "$preserve_bytes"; then
            if safe_path "$preserve_path" && [ "$resolved" = "$preserve_path" ] && cp -p "$preserve_path" "$work/preserve-current"; then
                commit_file "$preserve_path" "$preserve_bytes" "$work/preserve-current" || return 1
                log "Preserved original nonmatching certificate bytes after native regeneration: $preserve_path"
            else fail "Cannot safely preserve native output bytes: $preserve_path"; return 1; fi
        fi
        preserve_index=$((preserve_index + 1))
    done
}
platform_system_changed() { system_changed=1; }
distro_family() {
    case $1 in
        debian|ubuntu|linuxmint|pop|pop-os|kali|raspbian|raspios|zorin|devuan) printf '%s\n' debian;;
        rhel|fedora|centos|rocky|almalinux|ol|amzn) printf '%s\n' rhel;;
        arch|archlinux) printf '%s\n' arch;;
        opensuse*|sles|sled|suse) printf '%s\n' suse;;
        alpine) printf '%s\n' alpine;;
        *) return 1;;
    esac
}
platform_prepare() {
    system_changed=0 system_ready=0
    distro=unknown distro_id='' distro_like='' distro_version=''
    os_release=$root/etc/os-release
    [ -r "$os_release" ] || os_release=$root/usr/lib/os-release
    if [ -r "$os_release" ]; then
        # os-release is data, never executable shell input.
        distro_id=$(awk -F= '$1=="ID" {gsub(/["\047]/,"",$2); print tolower($2); exit}' "$os_release")
        distro_like=$(awk -F= '$1=="ID_LIKE" {gsub(/["\047]/,"",$2); print tolower($2); exit}' "$os_release")
        distro_version=$(awk -F= '$1=="VERSION" || $1=="NAME" {gsub(/["\047]/,"",$2); print tolower($2)}' "$os_release")
        for distro_candidate in $distro_id $distro_like; do
            if distro=$(distro_family "$distro_candidate"); then break; fi
            distro=unknown
        done
        if [ "$distro" = unknown ]; then
            case $distro_version in
                *debian*|*ubuntu*|*mint*|*raspberry*|*devuan*) distro=debian;;
                *amazon*|*red\ hat*|*fedora*|*centos*) distro=rhel;;
                *opensuse*|*suse*) distro=suse;;
                *arch\ linux*) distro=arch;;
                *alpine*) distro=alpine;;
            esac
        fi
    fi
    log "Linux distro: $distro (ID=$distro_id ID_LIKE=$distro_like)"
}
platform_system_backup() {
    [ "$system_ready" = 0 ] || return 0
    if [ -n "$root" ]; then
        if [ -n "${DEMUDHRA_TEST_REGEN:-}" ]; then
            case $DEMUDHRA_TEST_REGEN in /*) :;; *) fail 'TEST_REGEN must be an absolute shim path'; return 1;; esac
            [ -x "$DEMUDHRA_TEST_REGEN" ] || { fail 'TEST_REGEN shim is not executable'; return 1; }
            log '!!! WARNING: TEST-ONLY native regeneration shim active. No host updater will run. !!!'
            snapshot_system_outputs || return 1
        else log 'TEST ROOT: native host trust regeneration is suppressed.'; fi
        system_ready=1
        return 0
    fi
    case $distro in
        debian)
            command -v update-ca-certificates >/dev/null 2>&1 || { fail 'Missing update-ca-certificates'; return 1; }
            grep -q -- --hooksdir "$(command -v update-ca-certificates)" || { fail 'Cannot disable unknown update hooks; refusing system mutation'; return 1; };;
        alpine)
            command -v update-ca-certificates >/dev/null 2>&1 || { fail 'Missing update-ca-certificates'; return 1; }
            # Alpine hooks are arbitrary programs. Refuse unknown hook effects.
            if [ -d /etc/ca-certificates/update.d ] && [ -n "$(find /etc/ca-certificates/update.d \( -type f -o -type l \) ! -name java-cacerts -print)" ]; then
                fail 'Alpine custom update hooks cannot be safely backed up; remove/disable hooks explicitly first'; return 1
            fi;;
        rhel) command -v update-ca-trust >/dev/null 2>&1 || { fail 'Missing update-ca-trust'; return 1; };;
        arch) command -v update-ca-trust >/dev/null 2>&1 || command -v trust >/dev/null 2>&1 || { fail 'Missing update-ca-trust/trust'; return 1; };;
        suse)
            command -v update-ca-certificates >/dev/null 2>&1 || { fail 'Missing update-ca-certificates'; return 1; }
            if [ ! -L /etc/ssl/certs ] || [ "$(readlink /etc/ssl/certs)" != ../../var/lib/ca-certificates/pem ]; then
                fail 'SUSE /etc/ssl/certs has a custom layout; refusing native directory migration'; return 1
            fi
            for hook_dir in /etc/ca-certificates/update.d /usr/lib/ca-certificates/update.d; do
                for hook in "$hook_dir/"*.run; do
                    [ -e "$hook" ] || [ -L "$hook" ] || continue
                    if [ -L "$hook" ] && [ "$(readlink "$hook")" = /dev/null ]; then continue; fi
                    case $hook in
                        /usr/lib/ca-certificates/update.d/50java.run|/usr/lib/ca-certificates/update.d/70openssl.run|/usr/lib/ca-certificates/update.d/80etc_ssl.run|/usr/lib/ca-certificates/update.d/99certbundle.run) :;;
                        *) fail "Unknown SUSE update hook cannot be safely backed up: $hook"; return 1;;
                    esac
                done
            done;;
        *) fail "Unsupported system trust regeneration for $distro; use --no-system for bundled software"; return 1;;
    esac
    snapshot_system_outputs || return 1
    system_ready=1
}
snapshot_system_outputs() {
    for store_tree in /etc/ca-certificates/extracted /etc/ssl/certs /etc/pki/ca-trust/extracted /etc/pki/tls/certs /var/lib/ca-certificates /etc/ssl/java /etc/pki/ca-trust/source/blocklist /etc/pki/ca-trust/source/blacklist /etc/ca-certificates/trust-source/blocklist /etc/ca-certificates/trust-source/blacklist /etc/pki/trust/blocklist /etc/pki/trust/blacklist; do
        backup_tree "$root$store_tree" || return 1
    done
    if [ -f "$root/etc/pki/trust/.updated" ]; then backup_file "$root/etc/pki/trust/.updated" || return 1; fi
}
disable_packaged_certificate() {
    case $bundle in "$root/usr/share/ca-certificates/"*.crt) :;; *) return 0;; esac
    packaged_name=${bundle#"$root/usr/share/ca-certificates/"}
    config_path=$root/etc/ca-certificates.conf
    config_existed=0
    if [ -e "$config_path" ] || [ -L "$config_path" ]; then
        safe_path "$config_path" || { fail "Unsafe CA configuration: $config_path"; return 1; }
        config_path=$resolved
        cp -p "$config_path" "$work/ca-conf-original" || { fail "Cannot read $config_path"; return 1; }
        config_existed=1
    else
        : > "$work/ca-conf-original"
    fi
    # update-ca-certificates(8) uses !relative/path.crt to disable packaged CAs.
    # https://manpages.debian.org/testing/ca-certificates/update-ca-certificates.8.en.html
    DEMUDHRA_PACKAGED_NAME="$packaged_name" awk '
      BEGIN {cert=ENVIRON["DEMUDHRA_PACKAGED_NAME"]}
      $0==cert || $0=="!" cert {if(!written++) print "!" cert; next}
      {print}
      END {if(!written) print "!" cert}
    ' "$work/ca-conf-original" > "$work/ca-conf-new" || return 1
    if [ "$config_existed" = 1 ]; then
        if ! cmp -s "$work/ca-conf-original" "$work/ca-conf-new"; then
            commit_file "$config_path" "$work/ca-conf-new" "$work/ca-conf-original" || return 1
        fi
    else
        ensure_backup || return 1
        add_undo "rm -f $(quote "$config_path")" || return 1
        config_stage=$(mktemp "$(dirname "$config_path")/.demudhra-conf-XXXXXX") || { fail "Cannot stage $config_path"; return 1; }
        if ! cp "$work/ca-conf-new" "$config_stage" || ! chmod 644 "$config_stage" || ! mv "$config_stage" "$config_path"; then
            rm -f "$config_stage"; fail "Cannot disable packaged CA in $config_path"; return 1
        fi
    fi
    log "Persistent packaged CA disable: !$packaged_name in $config_path (fingerprint matched)"
}
choose_block_dirs() {
    block_dirs=''
    # Current manuals all name blocklist; older installations may use blacklist.
    # https://www.mankier.com/8/update-ca-trust
    # https://man.archlinux.org/man/update-ca-trust.8.en
    # https://manpages.opensuse.org/Tumbleweed/ca-certificates/update-ca-certificates.8.en.html
    for block_name in blocklist blacklist; do
        if [ -d "$root$block_base/$block_name" ]; then block_dirs="$block_dirs $block_name"; fi
    done
    [ -z "$block_dirs" ] || return 0
    : > "$work/trust-man"
    for man_file in "$root/usr/share/man/man8/update-ca-trust.8"* "$root/usr/share/man/man8/update-ca-certificates.8"*; do
        [ -r "$man_file" ] || continue
        case $man_file in
            *.gz) if command -v gzip >/dev/null 2>&1; then gzip -cd "$man_file" >> "$work/trust-man" 2>/dev/null || :; fi;;
            *.8) cat "$man_file" >> "$work/trust-man";;
        esac
    done
    for block_name in blocklist blacklist; do
        if grep -F -q "$block_base/$block_name" "$work/trust-man"; then block_dirs="$block_dirs $block_name"; fi
    done
    if [ -z "$block_dirs" ]; then
        block_dirs='blocklist blacklist'
        log "Installed distrust directory could not be confirmed; writing safe superset: $block_base/blocklist and $block_base/blacklist"
    fi
}
platform_block_matches() {
    case $distro in
        debian|alpine) disable_packaged_certificate; return $?;;
        rhel) block_base=/etc/pki/ca-trust/source;;
        arch) block_base=/etc/ca-certificates/trust-source;;
        suse) block_base=/etc/pki/trust;;
        *) return 0;;
    esac
    choose_block_dirs
    for block_name in $block_dirs; do
        block_dir=$root$block_base/$block_name
        for block_cert in "$work/system-match-"*.pem; do
            [ -f "$block_cert" ] || continue
            block_hash=$(fingerprint "$block_cert") || { fail 'Cannot hash persistent distrust record'; return 1; }
            block_path=$block_dir/demudhra-$block_hash.pem
            if [ -e "$block_path" ]; then
                existing_hash=$(fingerprint "$block_path") || { fail "Invalid existing distrust record: $block_path"; return 1; }
                [ "$existing_hash" = "$block_hash" ] || { fail "Conflicting distrust record: $block_path"; return 1; }
                continue
            fi
            ensure_backup || return 1
            add_undo "rm -f $(quote "$block_path")" || return 1
            mkdir -p "$block_dir" || { fail "Root required to create $block_dir"; return 1; }
            safe_path "$block_dir" || { fail "Unsafe distrust directory: $block_dir"; return 1; }
            block_stage=$(mktemp "$block_dir/.demudhra-XXXXXX") || { fail 'Cannot stage persistent distrust'; return 1; }
            if ! cp "$block_cert" "$block_stage" || ! chmod 644 "$block_stage" || ! mv "$block_stage" "$block_path"; then
                rm -f "$block_stage"; fail "Cannot write $block_path"; return 1
            fi
            log "Persistent exact-certificate distrust: $block_path"
        done
    done
}
platform_main() {
    [ "$system_changed" = 1 ] || return 0
    if [ -n "$root" ] && [ -z "${DEMUDHRA_TEST_REGEN:-}" ]; then return 0; fi
    log 'Regenerating native system trust from remaining anchors.'
    if [ -n "$root" ]; then
        "$DEMUDHRA_TEST_REGEN" "$root" > "$work/update.log" 2>&1
        status=$?
    else
    case $distro in
        debian) mkdir "$work/empty-hooks" && update-ca-certificates --fresh --hooksdir "$work/empty-hooks" > "$work/update.log" 2>&1; status=$?;;
        alpine) update-ca-certificates > "$work/update.log" 2>&1; status=$?;;
        suse) update-ca-certificates --fresh > "$work/update.log" 2>&1; status=$?;;
        rhel) update-ca-trust extract > "$work/update.log" 2>&1; status=$?;;
        arch)
            if command -v update-ca-trust >/dev/null 2>&1; then update-ca-trust extract > "$work/update.log" 2>&1
            else trust extract-compat > "$work/update.log" 2>&1; fi
            status=$?;;
        *) status=1;;
    esac
    fi
    [ ! -f "$work/update.log" ] || cat "$work/update.log"
    [ "$status" = 0 ] || { fail "System regeneration failed ($status)"; return; }
    # A source or compiled p11-kit module may restore a directly edited bundle.
    # Reinspect generated outputs without modifying them or counting twice.
    before=$found
    for generated in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem /var/lib/ca-certificates/ca-bundle.pem; do
        generated=$root$generated
        [ -f "$generated" ] || continue
        ecosystem=system
        inspect_bundle "$generated" report
    done
    if [ "$found" -gt "$before" ]; then
        fail 'Selected certificates returned after regeneration. A source/compiled trust module still supplies them; upgrade the CA package and rerun.'
    fi
    found=$before
    restore_system_bytes
}
