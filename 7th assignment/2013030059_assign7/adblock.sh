#!/usr/bin/env bash
# You are NOT allowed to change the files' names!
set -u

# Resolve data paths relative to the script, not the caller's working directory.
# domainNames.txt/IPAddresses.txt/adblockRules normally live beside this script;
# the fallback to the parent directory is kept only for a caller that still
# points this script at the old, pre-cleanup layout.
scriptDir=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
dataDir="$scriptDir"
if [[ ! -e "$dataDir/domainNames.txt" ]] && [[ -e "$scriptDir/../domainNames.txt" ]]; then
    dataDir="$scriptDir/.."
fi
domainNames="$dataDir/domainNames.txt"
IPAddresses="$dataDir/IPAddresses.txt"
adblockRules="$dataDir/adblockRules"
chainName="ADBLOCK"

fail() {
    printf 'Error: %s\n' "$*" >&2
    exit 1
}

requireCommand() {
    command -v "$1" >/dev/null 2>&1 || fail "required command '$1' was not found."
}

requireRoot() {
    [[ "$EUID" -eq 0 ]] || fail "this option requires root privileges."
}

validIPv4() {
    local ip=$1 part
    local -a parts
    [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    IFS=. read -r -a parts <<< "$ip"
    for part in "${parts[@]}"; do
        [[ $part =~ ^[0-9]{1,3}$ ]] || return 1
        (( 10#$part <= 255 )) || return 1
    done
}

printHelp() {
    printf 'A simple adblock mechanism using an isolated iptables chain.\n\n'
    printf 'Usage: %s [OPTION]\n\n' "$0"
    printf '  -domains  Resolve domainNames.txt into IPAddresses.txt and install rules.\n'
    printf '  -ips      Install rules from IPAddresses.txt.\n'
    printf '  -save     Save firewall rules to adblockRules.\n'
    printf '  -load     Validate and load rules from adblockRules.\n'
    printf '  -list     List rules managed by this script.\n'
    printf '  -reset    Remove rules managed by this script (accept all again).\n'
    printf '  -help     Display this help and exit.\n\n'
    printf 'Installed rules reject traffic to a blocked IP (OUTPUT) and traffic\n'
    printf 'from a blocked IP (INPUT), so neither a request nor a stray reply\n'
    printf 'from an ad domain gets through.\n'
}

resolveDomains() {
    local domain ip resolver temporaryFile

    [[ -r "$domainNames" ]] || fail "cannot read '$domainNames'."
    requireCommand awk
    requireCommand sort
    requireCommand mktemp
    if command -v getent >/dev/null 2>&1; then
        resolver=getent
    elif command -v host >/dev/null 2>&1; then
        resolver=host
    else
        fail "neither 'getent' nor 'host' is available for DNS resolution."
    fi

    temporaryFile=$(mktemp "${IPAddresses}.tmp.XXXXXX") || fail "cannot create a temporary file."
    trap 'rm -f -- "$temporaryFile"' EXIT
    while IFS= read -r domain || [[ -n "$domain" ]]; do
        domain=${domain%%#*}
        domain=${domain//$'\r'/}
        domain=${domain//[[:space:]]/}
        [[ -n "$domain" ]] || continue
        if [[ ! $domain =~ ^([[:alnum:]]([[:alnum:]-]*[[:alnum:]])?\.)+[[:alpha:]]{2,63}\.?$ ]]; then
            printf 'Warning: ignoring invalid domain: %s\n' "$domain" >&2
            continue
        fi
        if [[ "$resolver" = getent ]]; then
            while IFS= read -r ip; do
                validIPv4 "$ip" && printf '%s\n' "$ip" >> "$temporaryFile"
            done < <(getent ahostsv4 "$domain" 2>/dev/null | awk '{print $1}')
        else
            while IFS= read -r ip; do
                validIPv4 "$ip" && printf '%s\n' "$ip" >> "$temporaryFile"
            done < <(host -t A "$domain" 2>/dev/null | awk '/has address/ {print $4}')
        fi
    done < "$domainNames"

    sort -u "$temporaryFile" -o "$temporaryFile"
    [[ -s "$temporaryFile" ]] || fail "no domains resolved to IPv4 addresses."
    mv -- "$temporaryFile" "$IPAddresses" || fail "cannot replace '$IPAddresses'."
    trap - EXIT
    printf 'Wrote %s unique IPv4 addresses to %s.\n' "$(wc -l < "$IPAddresses")" "$IPAddresses"
}

configureIPs() {
    # Rejects traffic in both directions for every blocked IP: -d (as the
    # destination) covers OUTPUT, so a request to the ad server never leaves;
    # -s (as the source) covers INPUT, so a reply or unsolicited packet from
    # that IP is dropped too. Each direction's own rules are no-ops on the
    # other chain (OUTPUT never sees the ad server as a source, INPUT never
    # sees it as the local destination), so one chain safely serves both.
    local ip installed=0
    local -a addresses=()
    local -A seen=()

    requireRoot
    requireCommand iptables
    [[ -r "$IPAddresses" ]] || fail "cannot read '$IPAddresses'."
    # Validate the complete replacement before touching existing rules.
    while IFS= read -r ip || [[ -n "$ip" ]]; do
        ip=${ip%%#*}
        ip=${ip//[[:space:]]/}
        [[ -n "$ip" ]] || continue
        validIPv4 "$ip" || fail "invalid IPv4 address: $ip; no rules were changed."
        if [[ ! -v 'seen[$ip]' ]]; then
            addresses+=("$ip")
            seen[$ip]=1
        fi
    done < "$IPAddresses"
    (( ${#addresses[@]} > 0 )) || fail "no valid IPv4 addresses; no rules were changed."
    iptables -nL "$chainName" >/dev/null 2>&1 ||
        iptables -N "$chainName" || fail "could not create the $chainName chain."
    iptables -F "$chainName" || fail "could not clear the $chainName chain."
    iptables -C OUTPUT -j "$chainName" >/dev/null 2>&1 ||
        iptables -I OUTPUT 1 -j "$chainName" || fail "could not attach the $chainName chain to OUTPUT."
    iptables -C INPUT -j "$chainName" >/dev/null 2>&1 ||
        iptables -I INPUT 1 -j "$chainName" || fail "could not attach the $chainName chain to INPUT."

    for ip in "${addresses[@]}"; do
        iptables -A "$chainName" -d "$ip" -j REJECT || fail "failed to add an outbound rule for $ip."
        iptables -A "$chainName" -s "$ip" -j REJECT || fail "failed to add an inbound rule for $ip."
        ((installed += 1))
    done
    printf 'Installed rules for %d address(es) (%d total: OUTPUT + INPUT).\n' "$installed" "$((installed * 2))"
}

saveRules() {
    local temporaryFile
    requireRoot
    requireCommand iptables-save
    temporaryFile=$(mktemp "${adblockRules}.tmp.XXXXXX") || fail "cannot create a temporary file."
    trap 'rm -f -- "$temporaryFile"' EXIT
    iptables-save > "$temporaryFile" || fail "iptables-save failed."
    mv -- "$temporaryFile" "$adblockRules" || fail "cannot replace '$adblockRules'."
    trap - EXIT
    printf 'Saved firewall rules to %s.\n' "$adblockRules"
}

loadRules() {
    requireRoot
    [[ "${ADBLOCK_ALLOW_FULL_RESTORE:-0}" = 1 ]] ||
        fail "full firewall restore requires explicit ADBLOCK_ALLOW_FULL_RESTORE=1 approval."
    requireCommand iptables-restore
    [[ -s "$adblockRules" ]] || fail "'$adblockRules' is missing or empty."
    iptables-restore --test < "$adblockRules" || fail "rules validation failed; nothing was loaded."
    iptables-restore < "$adblockRules" || fail "iptables-restore failed."
    printf 'Loaded firewall rules from %s.\n' "$adblockRules"
}

resetRules() {
    requireRoot
    requireCommand iptables
    local hook
    for hook in OUTPUT INPUT; do
        while iptables -C "$hook" -j "$chainName" >/dev/null 2>&1; do
            iptables -D "$hook" -j "$chainName" || fail "could not detach the $chainName chain from $hook."
        done
    done
    if iptables -nL "$chainName" >/dev/null 2>&1; then
        iptables -F "$chainName" || fail "could not clear the $chainName chain."
        iptables -X "$chainName" || fail "could not remove the $chainName chain."
    fi
    printf 'Removed all rules managed by this script (accept all again).\n'
}

listRules() {
    requireRoot
    requireCommand iptables
    if ! iptables -nL "$chainName" >/dev/null 2>&1; then
        printf 'No rules installed (chain %s does not exist).\n' "$chainName"
        return 0
    fi
    iptables -S "$chainName" || fail "could not list current firewall rules."
}

adBlock() {
    [[ "$#" -eq 1 ]] || { printHelp >&2; return 1; }
    case $1 in
        -domains) resolveDomains && configureIPs ;;
        -ips) configureIPs ;;
        -save) saveRules ;;
        -load) loadRules ;;
        -reset) resetRules ;;
        -list) listRules ;;
        -help) printHelp ;;
        *) printf 'Wrong argument: %s\n' "$1" >&2; printHelp >&2; return 1 ;;
    esac
}

if [[ ${BASH_SOURCE[0]} == "$0" ]]; then
    adBlock "$@"
fi
