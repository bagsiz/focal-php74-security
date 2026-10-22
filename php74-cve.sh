#!/bin/bash
# Patched PHP 7.4 packages for CVE-2026-109618 / CVE-2026-109619 on Ubuntu 20.04 (focal)
#
# Usage:
#   ./php74-cve.sh status              show the PHP installs on this server and their patch status
#   ./php74-cve.sh install [-y]        upgrade the installed php7.4-* packages to the patched version
#   ./php74-cve.sh uninstall [-y]      roll back to the versions installed before
#
# The packages are Ondřej Surý's php7.4 1:7.4.33-31 (which carries the official fix),
# rebuilt for Ubuntu 20.04: the PPA no longer builds for focal, and Ubuntu's own
# 7.4.3-4ubuntu2.x only gets the fix through Ubuntu Pro (ESM).
# Only php7.4-* packages that are already installed are changed. If verification fails
# after install, the upgrade is rolled back automatically.
#
# USE AT YOUR OWN RISK. Unofficial rebuild, provided "AS IS", WITHOUT WARRANTY OF ANY KIND.
# The authors are not liable for any damage. See README.md and LICENSE:
# https://github.com/bagsiz/focal-php74-security
set -uo pipefail

PATCHED_VER='1:7.4.33-31+ubuntu20.04.1+bagsiz1'
CVE=CVE-2026-109618
HERE=$(cd "$(dirname "$0")" && pwd)
STATE_DIR=/var/lib/php74-cve-2026
DEB_DIR=$HERE/debs
CONF_PATHS="etc/php/7.4"
SERVICES="php7.4-fpm apache2 nginx"

# The .debs are a GitHub release asset: when debs/ is missing, the archive is downloaded
# and checked against the SHA256 below. Without access, download it by hand and put it
# next to this script.
RELEASE_URL=${PHP74CVE_RELEASE_URL:-https://github.com/bagsiz/focal-php74-security/releases/download/v7.4.33-31-focal1}
ASSET=php74-focal-debs.tar.gz
ASSET_SHA=59c2bfdd06a34c6872d346065ad68e4bd235d9dac00f4ab0631910d99e14c75b
# packages that have a patched build
PKGS="libapache2-mod-php7.4 libphp7.4-embed php7.4 php7.4-bcmath php7.4-bz2 php7.4-cgi php7.4-cli php7.4-common php7.4-curl php7.4-dba php7.4-dev php7.4-enchant php7.4-fpm php7.4-gd php7.4-gmp php7.4-imap php7.4-interbase php7.4-intl php7.4-json php7.4-ldap php7.4-litespeed php7.4-mbstring php7.4-mysql php7.4-odbc php7.4-opcache php7.4-pgsql php7.4-phpdbg php7.4-pspell php7.4-readline php7.4-snmp php7.4-soap php7.4-sqlite3 php7.4-sybase php7.4-tidy php7.4-xml php7.4-xmlrpc php7.4-xsl php7.4-zip"

# Network timeouts (seconds): curl gives up when it cannot connect, or when the download
# stalls (below 1 KB/s), for NET_TIMEOUT seconds. apt: per-request timeout, one retry.
NET_TIMEOUT=${PHP74CVE_NET_TIMEOUT:-10}
CURL_NET=(--connect-timeout "$NET_TIMEOUT" --speed-time "$NET_TIMEOUT" --speed-limit 1024)
APT_NET=(-o Acquire::http::Timeout="$NET_TIMEOUT" -o Acquire::https::Timeout="$NET_TIMEOUT" -o Acquire::Retries=1)
# apt runs non-interactively; needrestart only lists, this script restarts the services itself
export DEBIAN_FRONTEND=noninteractive NEEDRESTART_MODE=l NEEDRESTART_SUSPEND=1

ASSUME_YES=0
CMD=${1:-status}
[ "${2:-}" = "-y" ] && ASSUME_YES=1

say()  { printf '\033[1m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mWARNING:\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }
confirm() {
    [ "$ASSUME_YES" = 1 ] && return 0
    read -r -p "$1 [y/N] " a
    [ "$a" = y ] || [ "$a" = Y ]
}

# "NAME VERSION" of installed php7.4-* / libapache2-mod-php7.4 packages
installed_pkgs() {
    dpkg-query -W -f='${db:Status-Abbrev} ${Package} ${Version}\n' 'php7.4*' 'libapache2-mod-php7.4' 2>/dev/null \
        | awk '$1 == "ii" {print $2, $3}' | sort
}

deb_of() { # NAME -> path of the patched .deb, if shipped
    local f
    for f in "$DEB_DIR/${1}_${PATCHED_VER#*:}_"*.deb; do [ -f "$f" ] && { echo "$f"; return 0; }; done
    return 1
}

has_patched() { # NAME: is there a patched build of this package
    case " $PKGS " in *" $1 "*) return 0 ;; esac
    return 1
}

is_patched() { [ "$(dpkg-query -W -f='${Version}' "$1" 2>/dev/null)" = "$PATCHED_VER" ]; }

active_services() {
    local s
    for s in $SERVICES; do systemctl is-active --quiet "$s" >/dev/null 2>&1 && echo "$s"; done
}

preflight() {
    [ "$(id -u)" = 0 ] || die "run as root"
    grep -q '^VERSION_CODENAME=focal' /etc/os-release 2>/dev/null || die "Ubuntu 20.04 (focal) only"
    [ "$(dpkg --print-architecture)" = amd64 ] || die "amd64 only"
}

# download the release archive when debs/ is missing, verify it, extract it
fetch_debs() {
    [ -f "$DEB_DIR/SHA256SUMS" ] && return 0
    local f=$HERE/$ASSET
    if [ ! -f "$f" ]; then
        say "Downloading packages: $RELEASE_URL/$ASSET"
        curl -fL "${CURL_NET[@]}" -o "$f.part" "$RELEASE_URL/$ASSET" && mv "$f.part" "$f" || {
            rm -f "$f.part"
            die "could not download $ASSET. Download it from the release by hand, put it in $HERE/ and run again"
        }
    fi
    echo "$ASSET_SHA  $f" | sha256sum --quiet -c - || die "$ASSET SHA256 mismatch (corrupted or modified); delete it and download again"
    tar xzf "$f" -C "$HERE" || die "could not extract $ASSET"
}

# Finds every PHP on the server and how it is used. Each line: KIND|DESCRIPTION
# KIND: patchable (Ubuntu or Sury php7.4 package), - (left as is)
discover() {
    local cands=() p f real how pid exe conf cmd own ver kind ppid_
    local -A hows=() order=()
    local n=0
    for p in php php7.4 php-fpm7.4 php-cgi php-cgi7.4; do
        f=$(command -v "$p" 2>/dev/null) && cands+=("$f|command '$p'")
    done
    for f in /usr/bin/php* /usr/sbin/php-fpm* /usr/local/bin/php* /usr/local/sbin/php-fpm* \
             /usr/local/php*/bin/php /opt/php*/bin/php /usr/local/lsws/lsphp*/bin/php; do
        [ -f "$f" ] && [ -x "$f" ] || continue
        case "${f##*/}" in
            php|php[0-9]|php[0-9].[0-9]|php-fpm*|php-cgi*|php[0-9]*-cgi) cands+=("$f|$f") ;;
        esac
    done
    # running php-fpm master processes
    for p in /proc/[0-9]*; do
        cmd=$(tr '\0' ' ' < "$p/cmdline" 2>/dev/null) || continue
        pid=${p#/proc/}
        exe=$(readlink -f "$p/exe" 2>/dev/null)
        case "$cmd" in
            "php-fpm: master"*) ;;
            /*)
                case "${cmd%% *}" in */php-fpm*) ;; *) continue ;; esac
                ppid_=$(awk '/^PPid:/{print $2}' "$p/status" 2>/dev/null)
                case "$(tr '\0' ' ' < "/proc/$ppid_/cmdline" 2>/dev/null)" in *php-fpm*) continue ;; esac
                [ -n "$exe" ] || exe=${cmd%% *}
                ;;
            *) continue ;;
        esac
        [ -n "$exe" ] || continue
        conf=$(echo "$cmd" | sed -n 's/.*(\(.*\)).*/\1/p')
        cands+=("$exe|RUNNING: php-fpm master pid $pid${conf:+ ($conf)}")
    done
    # Apache mod_php
    for f in /etc/apache2/mods-enabled/php*.load; do
        [ -f "$f" ] || continue
        p=$(sed -n 's/^[[:space:]]*LoadModule[[:space:]]\+php[0-9_]*module[[:space:]]\+\([^[:space:]]\+\).*/\1/p' "$f")
        [ -n "$p" ] && cands+=("$(readlink -f "$p")|Apache module ($f)")
    done

    [ ${#cands[@]} -gt 0 ] || return 0
    for p in "${cands[@]}"; do
        f=${p%%|*}; how=${p#*|}
        real=$(readlink -f "$f" 2>/dev/null || echo "$f")
        [ "$how" = "$f" ] && { [ "$f" = "$real" ] && how="" || how="link: $f"; }
        if [ -z "${order[$real]+x}" ]; then order[$real]=$n; n=$((n+1)); hows[$real]=$how
        elif [ -n "$how" ]; then
            case "; ${hows[$real]}; " in *"; $how; "*) ;; *) hows[$real]="${hows[$real]:+${hows[$real]}; }$how" ;; esac
        fi
    done
    for real in $(for r in "${!order[@]}"; do echo "${order[$r]} $r"; done | sort -n | cut -d' ' -f2-); do
        how=${hows[$real]}
        own=$(dpkg -S "$real" 2>/dev/null | head -1 | cut -d: -f1)
        case "$real" in *.so) ver="" ;; *) ver=$("$real" -v 2>/dev/null | head -1); ver=${ver#PHP }; ver=${ver%% *} ;; esac
        case "$own" in
            php7.4-*|libapache2-mod-php7.4) kind=patchable ;;
            "")  kind="not owned by any package: built from source / copied by hand (not supported)" ;;
            *)   kind="package $own (not PHP 7.4, not handled here)" ;;
        esac
        f="$real  [PHP ${ver:-?}]${how:+  ($how)}"
        case "$kind" in patchable) echo "patchable|$f" ;; *) echo "-|$f : $kind" ;; esac
    done
}

print_discovery() {
    local line found=0
    say "PHP on this server"
    while IFS= read -r line; do
        [ -n "$line" ] || continue
        found=1
        case ${line%%|*} in
            patchable) echo "  [patchable ] ${line#*|}" ;;
            *)         echo "  [left as is] ${line#*|}" ;;
        esac
    done < <(discover)
    [ "$found" = 1 ] || echo "  (no PHP found)"
    if command -v docker >/dev/null 2>&1 && [ -n "$(docker ps -q 2>/dev/null)" ]; then
        echo "  note: Docker containers are running; PHP inside containers is not checked or changed by this script"
    fi
}

status_mode() {
    local name ver mark any=0
    say "Installed PHP 7.4 packages"
    while read -r name ver; do
        any=1
        if [ "$ver" = "$PATCHED_VER" ]; then mark="patched"
        elif has_patched "$name"; then mark="UNPATCHED (patched build available)"
        else mark="left as is (not shipped here)"; fi
        printf '  %-28s %-38s %s\n' "$name" "$ver" "$mark"
    done < <(installed_pkgs)
    [ "$any" = 1 ] || echo "  (none)"
    say "Services"
    for s in $SERVICES; do printf '  %-14s %s\n' "$s" "$(systemctl is-active "$s" 2>/dev/null || true)"; done
    [ -L "$STATE_DIR/current" ] && say "Backup of the last install: $(readlink "$STATE_DIR/current")"
    return 0
}

# Back up the .deb of an installed version, for rollback. Sources, in order:
#   cache : the apt cache (/var/cache/apt/archives)
#   repo  : the repositories (apt-get download NAME=VERSION)
#   repack: dpkg-repack, rebuilds the .deb from the installed files (unsigned;
#           config files go in as they are now)
# Prints the source used; returns 1 if none worked.
backup_deb() { # NAME VERSION DESTDIR
    local name=$1 ver=$2 dest=$3 src f tmp
    local sources=${PHP74CVE_BACKUP_SOURCES:-cache repo repack}
    [ -n "${PHP74CVE_NO_DOWNLOAD:-}" ] && sources=""
    for src in $sources; do
        case $src in
        cache)
            for f in /var/cache/apt/archives/"${name}_"*.deb; do
                [ -f "$f" ] || continue
                [ "$(dpkg-deb -f "$f" Package Version 2>/dev/null | awk '{print $2}' | tr '\n' ' ')" = "$name $ver " ] || continue
                cp "$f" "$dest/" && { echo cache; return 0; }
            done
            ;;
        repo)
            (cd "$dest" && apt-get "${APT_NET[@]}" -q download "$name=$ver" >/dev/null 2>&1) && ls "$dest/${name}_"*.deb >/dev/null 2>&1 && { echo repo; return 0; }
            ;;
        repack)
            command -v dpkg-repack >/dev/null 2>&1 || apt-get "${APT_NET[@]}" install -y -qq dpkg-repack >/dev/null 2>&1
            command -v dpkg-repack >/dev/null 2>&1 || continue
            tmp=$(mktemp -d)
            if (cd "$tmp" && dpkg-repack "$name" >/dev/null 2>&1); then
                f=$(ls "$tmp/${name}_"*.deb 2>/dev/null | head -1)
                [ -n "$f" ] && mv "$f" "$dest/" && { rm -rf "$tmp"; echo repack; return 0; }
            fi
            rm -rf "$tmp"
            ;;
        esac
    done
    return 1
}

# post-install checks; returns 1 on failure
verify() {
    local ok=0 out
    say "Verifying"
    if command -v php7.4 >/dev/null 2>&1; then
        if out=$(php7.4 -v 2>&1); then echo "  php7.4 -v: $(echo "$out" | head -1)"; else echo "  php7.4 -v FAILED: $out"; ok=1; fi
        out=$(php7.4 -m 2>&1 | grep -iE 'warning|error|fatal|unable to')
        if [ -n "$out" ]; then echo "  php7.4 -m reported warnings/errors:"; echo "$out" | sed 's/^/    /'; ok=1; else echo "  modules: loaded without warnings"; fi
    else
        echo "  php7.4 -v / -m: skipped (php7.4-cli not installed)"
    fi
    if zcat /usr/share/doc/php7.4-common/changelog.Debian.gz 2>/dev/null | grep -q "$CVE"; then echo "  changelog: contains $CVE"; else echo "  changelog: $CVE MISSING"; ok=1; fi
    if command -v php-fpm7.4 >/dev/null 2>&1; then
        if out=$(php-fpm7.4 -t 2>&1); then echo "  php-fpm7.4 -t: ok"; else echo "  php-fpm7.4 -t FAILED:"; echo "$out" | sed 's/^/    /'; ok=1; fi
    fi
    if systemctl is-active --quiet nginx >/dev/null 2>&1; then
        if out=$(nginx -t 2>&1); then echo "  nginx -t: ok"; else echo "  nginx -t FAILED:"; echo "$out" | sed 's/^/    /'; ok=1; fi
    fi
    if systemctl is-active --quiet apache2 >/dev/null 2>&1; then
        if out=$(apache2ctl -t 2>&1); then echo "  apache2ctl -t: ok"; else echo "  apache2ctl -t FAILED:"; echo "$out" | sed 's/^/    /'; ok=1; fi
    fi
    # testing only: exercise the automatic rollback path
    [ -n "${PHP74CVE_TEST_FAIL_VERIFY:-}" ] && { echo "  (test) verification forced to fail"; ok=1; }
    return $ok
}

restart_services() {
    local s ok=0
    for s in "$@"; do
        # nginx does not embed PHP: nothing to restart
        [ "$s" = nginx ] && continue
        say "Restarting $s"
        if systemctl restart "$s" && sleep 2 && systemctl is-active --quiet "$s" >/dev/null 2>&1; then
            echo "  $s: active"
        else
            echo "  $s: FAILED TO START"; systemctl status "$s" --no-pager -l 2>&1 | tail -15 | sed 's/^/    /'; ok=1
        fi
    done
    return $ok
}

cmd_install() {
    fetch_debs
    say "Checking package integrity"
    (cd "$DEB_DIR" && sha256sum --quiet -c SHA256SUMS) || die ".deb files are corrupted or modified"

    local name ver f files=() upgrade=() skipped=()
    while read -r name ver; do
        is_patched "$name" && continue
        if has_patched "$name"; then
            f=$(deb_of "$name") || die "patched .deb for $name is missing in $DEB_DIR"
            files+=("$f"); upgrade+=("$name $ver")
        else
            skipped+=("$name $ver")
        fi
    done < <(installed_pkgs)

    if [ ${#upgrade[@]} -eq 0 ]; then
        say "Nothing to upgrade, the installed php7.4 packages are already patched"
        return 0
    fi
    say "Packages to upgrade (-> $PATCHED_VER)"
    printf '  %s\n' "${upgrade[@]}"
    if [ ${#skipped[@]} -gt 0 ]; then say "Packages left as is"; printf '  %s\n' "${skipped[@]}"; fi

    if command -v php-fpm7.4 >/dev/null 2>&1 && ! php-fpm7.4 -t >/dev/null 2>&1; then
        php-fpm7.4 -t
        die "the php-fpm7.4 configuration is already broken BEFORE the install; fix that first"
    fi

    local services
    services=$(active_services)
    say "Services to restart after the install: $(echo $services | sed 's/\bnginx\b//')"
    confirm "Continue?" || die "aborted"

    local backup=$STATE_DIR/backup-$(date +%Y%m%d-%H%M%S) line src
    mkdir -p "$backup/debs"
    say "Creating backup: $backup"
    printf '%s\n' "${upgrade[@]}" > "$backup/upgraded.txt"
    echo "$services" > "$backup/services.txt"
    [ -e "/$CONF_PATHS" ] && tar czf "$backup/config.tar.gz" -C / $CONF_PATHS 2>/dev/null && echo "  configuration: $backup/config.tar.gz"

    local missing=()
    for line in "${upgrade[@]}"; do
        set -- $line
        if src=$(backup_deb "$1" "$2" "$backup/debs"); then
            echo "$1 $2 $src" >> "$backup/sources.txt"
            printf '  %-48s %s\n' "$1 $2" "$src"
        else
            missing+=("$1 $2")
        fi
    done
    echo "  packages of the current versions: $(( ${#upgrade[@]} - ${#missing[@]} ))/${#upgrade[@]} backed up"
    grep -q ' repack$' "$backup/sources.txt" 2>/dev/null && warn "some packages were rebuilt from the installed files with dpkg-repack (unsigned, not identical to the original)"
    if [ ${#missing[@]} -gt 0 ]; then
        warn "These versions could not be backed up:"
        printf '    %s\n' "${missing[@]}" >&2
        warn "uninstall will try to install them from the repositories by version"
        confirm "Continue anyway?" || { rm -rf "$backup"; die "aborted"; }
    fi
    mkdir -p "$STATE_DIR" && ln -sfn "$backup" "$STATE_DIR/current"

    say "Installing the patched packages"
    if ! apt-get "${APT_NET[@]}" install -y -q -o Dpkg::Options::=--force-confold "${files[@]}"; then
        die "apt install failed. Backup: $backup; check 'dpkg --audit' and run '$0 uninstall' if packages were changed"
    fi

    local failed=0
    verify || failed=1
    if [ "$failed" = 0 ] && [ -n "$services" ]; then restart_services $services || failed=1; fi
    if [ "$failed" = 1 ]; then
        warn "Verification failed, rolling back automatically"
        ASSUME_YES=1 cmd_uninstall
        die "the install was rolled back"
    fi
    say "Done: php7.4 upgraded to the patched version ($PATCHED_VER)"
    say "To roll back: $0 uninstall"
}

cmd_uninstall() {
    [ -L "$STATE_DIR/current" ] || die "nothing to roll back ($STATE_DIR); nothing was installed by this script"
    local backup name ver local_debs=() by_version=() f s
    backup=$(readlink "$STATE_DIR/current")
    [ -f "$backup/upgraded.txt" ] || die "$backup/upgraded.txt is missing"
    while read -r name ver; do
        is_patched "$name" || continue
        f=$(ls "$backup/debs/${name}_"*.deb 2>/dev/null | head -1)
        if [ -n "$f" ]; then local_debs+=("$f"); else by_version+=("$name=$ver"); fi
    done < "$backup/upgraded.txt"

    if [ ${#local_debs[@]} -eq 0 ] && [ ${#by_version[@]} -eq 0 ]; then
        say "No patched packages to roll back"; rm -f "$STATE_DIR/current"; return 0
    fi
    say "Rolling back to"
    for f in ${local_debs[@]+"${local_debs[@]}"}; do
        s=$(awk -v n="$(dpkg-deb -f "$f" Package)" '$1 == n {print $3}' "$backup/sources.txt" 2>/dev/null)
        printf '  %s (from backup%s)\n' "${f##*/}" "${s:+: $s}"
    done
    [ ${#by_version[@]} -gt 0 ] && printf '  %s (from the repositories)\n' "${by_version[@]}"
    confirm "Continue?" || die "aborted"

    apt-get "${APT_NET[@]}" install -y -q --allow-downgrades -o Dpkg::Options::=--force-confold \
        ${local_debs[@]+"${local_debs[@]}"} ${by_version[@]+"${by_version[@]}"} || die "apt downgrade failed"

    local services
    services=$(cat "$backup/services.txt" 2>/dev/null)
    [ -n "$services" ] && restart_services $services
    rm -f "$STATE_DIR/current"
    say "Rolled back. Configuration backup: $backup/config.tar.gz (not restored automatically)"
}

case "$CMD" in
    status)
        print_discovery; status_mode ;;
    install)
        preflight
        print_discovery
        [ -n "$(installed_pkgs)" ] || die "no php7.4 packages installed"
        cmd_install ;;
    uninstall)
        preflight; cmd_uninstall ;;
    *) sed -n '2,7p' "$0"; exit 2 ;;
esac
