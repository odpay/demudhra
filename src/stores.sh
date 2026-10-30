# shellcheck shell=sh
# shellcheck disable=SC2154
store_plan_save() {
    store_plan_count=$(($(wc -l < "$work/store-plans") + 1))
    store_plan=$work/store-$store_plan_count
    mkdir "$store_plan" || return 1
    for store_file in "$work/$1-"*; do cp -pR "$store_file" "$store_plan/" || return 1; done
    printf '%s\n' "$3" > "$store_plan/hits"
    printf '%s\t%s\n' "$2" "$store_plan_count" >> "$work/store-plans"
}
store_plan_load() {
    store_plan=$(DEMUDHRA_LOOKUP_PATH="$2" awk -F '\t' '$1==ENVIRON["DEMUDHRA_LOOKUP_PATH"] {print $2; exit}' "$work/store-plans")
    [ -n "$store_plan" ] || { fail "No reviewed store plan: $2"; return 1; }
    store_plan=$work/store-$store_plan
    rm -rf "$work/$1-"*
    for store_file in "$store_plan/$1-"*; do cp -pR "$store_file" "$work/" || return 1; done
    store_hits=$(cat "$store_plan/hits")
}
inspect_java() {
    java_store=$1
    if [ "$apply" = 1 ]; then
        store_plan_load java "$java_store" || return
        java_hits=$store_hits
        if ! cmp -s "$java_store" "$work/java-original"; then fail "Changed during scan, left unchanged: $java_store"; return; fi
        found=$((found + java_hits))
        apply_java
        return
    fi
    if ! command -v keytool >/dev/null 2>&1; then fail "Java keytool unavailable; cannot inspect $java_store"; immutable=$((immutable + 1)); return; fi
    if ! cp -p "$java_store" "$work/java-original"; then fail "Cannot snapshot Java store: $java_store"; return; fi
    if ! keytool -J-Duser.language=en -J-Duser.country=US -list -rfc -keystore "$work/java-original" -storepass changeit > "$work/java-list" 2> "$work/java.err"; then
        fail "Cannot inspect Java store (locked, custom password, or unsupported format): $java_store"
        immutable=$((immutable + 1)); return
    fi
    mkdir -p "$work/java-certs"
    rm -f "$work/java-certs/"*
    if ! awk -v dir="$work/java-certs" '
      /^Alias name: / {alias=substr($0,13); type=""}
      /^Entry type: / {type=substr($0,13)}
      /^-----BEGIN CERTIFICATE-----/ {n++; f=dir "/" n ".pem"; print alias > (dir "/" n ".alias"); close(dir "/" n ".alias"); print type > (dir "/" n ".type"); close(dir "/" n ".type"); cert=1}
      cert {print > f}
      /^-----END CERTIFICATE-----/ {close(f); cert=0}
      END {if(cert) exit 1}' "$work/java-list"; then fail "Malformed Java export: $java_store"; return; fi
    java_hits=0
    : > "$work/java-remove"
    for java_cert in "$work/java-certs/"*.pem; do
        [ -f "$java_cert" ] || continue
        hash=$(fingerprint "$java_cert") || { fail "Invalid Java certificate: $java_store"; return; }
        if selected "$hash"; then
            java_alias=$(cat "${java_cert%.pem}.alias")
            java_type=$(cat "${java_cert%.pem}.type")
            match_place java "$java_store" 1
            found=$((found + 1))
            log "FOUND java $hash $java_store alias=$(quote "$java_alias")"
            if [ "$java_type" != trustedCertEntry ] || ! plain_path "$java_alias"; then
                fail "Java alias contains a private key or unsafe name; certificate-only scope leaves it unchanged: $java_store"
                continue
            fi
            printf '%s\n' "$java_alias" >> "$work/java-remove"
            java_hits=$((java_hits + 1))
        fi
    done
    [ "$java_hits" -gt 0 ] || return 0
    log "Would remove $java_hits Java trusted certificate alias(es) from $java_store"
    store_plan_save java "$java_store" "$java_hits" || fail "Cannot save reviewed Java store: $java_store"
}
apply_java() {
    if ! cp -p "$work/java-original" "$work/java-new"; then fail "Cannot stage Java store: $java_store"; return; fi
    while IFS= read -r java_alias; do
        if ! keytool -J-Duser.language=en -delete -alias "$java_alias" -keystore "$work/java-new" -storepass changeit > "$work/java-delete.log" 2>&1; then
            fail "Java deletion failed on staged copy: $java_store"; return
        fi
    done < "$work/java-remove"
    if commit_file "$java_store" "$work/java-new" "$work/java-original"; then removed=$((removed + java_hits)); fi
}
inspect_nss() {
    nss_file=$1
    nss_dir=$(dirname "$nss_file")
    case $nss_file in */cert9.db) nss_mode=sql;; *) nss_mode=dbm;; esac
    if [ "$apply" = 1 ]; then
        store_plan_load nss "$nss_file" || return
        nss_hits=$store_hits
        for lock in "$nss_dir/.parentlock" "$nss_dir/parent.lock" "$nss_dir/lock" "$nss_dir/cert9.db-wal" "$nss_dir/cert9.db-shm"; do
            if [ -e "$lock" ] || [ -L "$lock" ]; then fail "Close NSS consumers before removal (busy store): $nss_dir"; return; fi
        done
        found=$((found + nss_hits))
        apply_nss
        return
    fi
    if ! command -v certutil >/dev/null 2>&1; then
        log "Cannot inspect NSS $nss_dir. Manual step: install certutil (NSS tools), close the browser, then rerun. Built-in roots need an NSS/browser update."
        immutable=$((immutable + 1)); manual_remaining=$((manual_remaining + 1)); return
    fi
    case $nss_file in */cert9.db) nss_mode=sql;; *) nss_mode=dbm;; esac
    for lock in "$nss_dir/.parentlock" "$nss_dir/parent.lock" "$nss_dir/lock" "$nss_dir/cert9.db-wal" "$nss_dir/cert9.db-shm"; do
        if [ -e "$lock" ] || [ -L "$lock" ]; then fail "Close NSS consumers before inspection (busy store): $nss_dir"; return; fi
    done
    mkdir -p "$work/nss-copy" "$work/nss-originals"
    rm -f "$work/nss-copy/"* "$work/nss-originals/"*
    for dbfile in cert9.db key4.db pkcs11.txt cert8.db key3.db secmod.db; do
        [ ! -f "$nss_dir/$dbfile" ] || { cp -p "$nss_dir/$dbfile" "$work/nss-copy/" && cp -p "$nss_dir/$dbfile" "$work/nss-originals/"; } || { fail "Cannot copy NSS store: $nss_dir"; return; }
    done
    # certutil may initialize or migrate a DB even when listing. Inspect only copies.
    if ! certutil -L -d "$nss_mode:$work/nss-copy" > "$work/nss-list" 2> "$work/nss.err"; then fail "Cannot list NSS database: $nss_dir"; return; fi
    sed -n 's/[[:space:]][[:space:]]*\([A-Za-z]*,[A-Za-z]*,[A-Za-z]*\)[[:space:]]*$//p' "$work/nss-list" > "$work/nss-aliases"
    : > "$work/nss-remove"
    : > "$work/nss-hashes"
    nss_hits=0
    nss_inspection_failed=0
    while IFS= read -r nickname; do
        [ -n "$nickname" ] || continue
        if ! certutil -L -d "$nss_mode:$work/nss-copy" -n "$nickname" -a > "$work/nss-cert" 2> "$work/nss.err"; then fail "Cannot export NSS nickname in $nss_dir"; nss_inspection_failed=1; continue; fi
        hash=$(fingerprint "$work/nss-cert") || { fail "Cannot parse NSS cert in $nss_dir"; nss_inspection_failed=1; continue; }
        # NSS can resolve distinct same-subject nicknames to the newest cert.
        # Duplicate exports mean the nickname interface cannot inventory safely.
        if grep -F -x -q "$hash" "$work/nss-hashes"; then
            fail "Ambiguous NSS nickname exports; manual inspection required, store unchanged: $nss_dir"
            nss_inspection_failed=1
        fi
        printf '%s\n' "$hash" >> "$work/nss-hashes"
        if selected "$hash"; then
            match_place nss "$nss_file" 1
            found=$((found + 1)); nss_hits=$((nss_hits + 1))
            log "FOUND nss $hash $nss_dir nickname=$(quote "$nickname")"
            printf '%s\t%s\n' "$hash" "$nickname" >> "$work/nss-remove"
        fi
    done < "$work/nss-aliases"
    [ "$nss_inspection_failed" = 0 ] || return 0
    [ "$nss_hits" -gt 0 ] || return 0
    log "Would remove $nss_hits NSS certificate(s) from $nss_dir. Close browsers first."
    store_plan_save nss "$nss_file" "$nss_hits" || fail "Cannot save reviewed NSS store: $nss_dir"
}
apply_nss() {
    while IFS="$(printf '\t')" read -r expected_hash nickname; do
        if ! certutil -L -d "$nss_mode:$work/nss-copy" -n "$nickname" -a > "$work/nss-cert" 2> "$work/nss.err"; then
            fail "Cannot reverify staged NSS nickname: $nss_dir"; return
        fi
        hash=$(fingerprint "$work/nss-cert") || { fail "Invalid staged NSS certificate: $nss_dir"; return; }
        [ "$hash" = "$expected_hash" ] || { fail "Staged NSS nickname changed identity; store unchanged: $nss_dir"; return; }
        certutil -D -d "$nss_mode:$work/nss-copy" -n "$nickname" > "$work/nss-delete.log" 2>&1 || { fail "NSS deletion failed on staged database: $nss_dir"; return; }
    done < "$work/nss-remove"
    for dbfile in cert9.db key4.db pkcs11.txt cert8.db key3.db secmod.db; do
        if [ -f "$work/nss-originals/$dbfile" ] && ! cmp -s "$nss_dir/$dbfile" "$work/nss-originals/$dbfile"; then
            fail "NSS database changed during inspection, left unchanged: $nss_dir"; return
        fi
    done
    # Snapshot every native store component before replacing any component.
    for dbfile in cert9.db key4.db pkcs11.txt cert8.db key3.db secmod.db; do
        [ ! -f "$nss_dir/$dbfile" ] || backup_file "$nss_dir/$dbfile" || return
    done
    for dbfile in cert9.db key4.db pkcs11.txt cert8.db key3.db secmod.db; do
        if [ -f "$nss_dir/$dbfile" ] && [ -f "$work/nss-copy/$dbfile" ]; then
            commit_file "$nss_dir/$dbfile" "$work/nss-copy/$dbfile" "$work/nss-originals/$dbfile" || return
        fi
    done
    removed=$((removed + nss_hits))
    log 'NSS built-in roots are provided by the library. Upgrade NSS; profile deletion cannot remove compiled roots.'
    immutable=$((immutable + 1))
}
