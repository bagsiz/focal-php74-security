# focal-php74-security

Patched PHP 7.4 packages for **Ubuntu 20.04 (focal)** fixing
**CVE-2026-109618** and **CVE-2026-109619** (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp).
The repo also includes an installer that finds the PHP installs on a server, upgrades
them and can roll the upgrade back.

## Why this exists

Ubuntu 20.04 left standard support in May 2025. Its `php7.4` packages
(`7.4.3-4ubuntu2.x`) now get security fixes only through Ubuntu Pro (ESM). Ondřej Surý's
PHP PPA published the fix as `1:7.4.33-31` on 2026-10-21, but the PPA no longer builds for
focal. So a focal server without Ubuntu Pro has no patched `php7.4` to install.

These packages are **Ondřej Surý's `php7.4 1:7.4.33-31` source package rebuilt for
Ubuntu 20.04 without changes**. Only the version string was extended and a changelog entry
added:

```
1:7.4.33-31+ubuntu20.04.1+bagsiz1
```

Moving from Ubuntu's 7.4.3 to 7.4.33 also brings 30 upstream bug-fix releases of the 7.4
branch, plus every security fix that Ondřej Surý backported to 7.4 after upstream EOL.
These include the CVE-2026-91768 and CVE-2025-1218 fixes. A focal server without Ubuntu
Pro has not received any of these since May 2025.

> ⚠️ PHP 7.4 has been end-of-life since November 2022 and Ubuntu 20.04 since May 2025.
> This is a stop-gap. The real fix is to move to a supported Ubuntu and PHP version.

## Quick start

```bash
curl -fLO https://raw.githubusercontent.com/bagsiz/focal-php74-security/main/php74-cve.sh
chmod +x php74-cve.sh

./php74-cve.sh status      # list every PHP on the server and its patch status
./php74-cve.sh install     # upgrade the installed php7.4 packages (asks for confirmation; -y to skip)
./php74-cve.sh uninstall   # roll back to the previous versions
```

The `.deb` files are published as a [release asset](https://github.com/bagsiz/focal-php74-security/releases/tag/v7.4.33-31-focal1)
(`php74-focal-debs.tar.gz`). `install` downloads it and checks it against a SHA256 that is
hardcoded in the script, then checks each `.deb` against `SHA256SUMS`. If the server has
no internet access, download the archive by hand and put it next to the script.

## What it detects

`status` and `install` start by listing every PHP they can find on the server:

- the `php`, `php7.4`, `php-fpm7.4` and `php-cgi` commands
- copies under `/usr/local` and `/opt`
- running `php-fpm` master processes
- Apache mod_php

Each one is matched to the `.deb` package that owns it:

| Found | Action |
|---|---|
| `php7.4-*` / `libapache2-mod-php7.4` from Ubuntu or Ondřej Surý's PPA | upgraded |
| Other PHP versions, source builds | reported only, not changed |
| PHP inside Docker containers | not checked or changed. The script prints a note when containers are running |

The script only replaces `php7.4-*` packages that are already installed. Ubuntu's `php-*`
metapackages (`php-fpm`, `php-curl`, …, `2:7.4+75`) stay as they are and keep working:
the new packages need `php-common (>= 1:81~)`, and Ubuntu's `php-common 2:75` satisfies
that because of its higher epoch. Later `apt upgrade` runs keep these packages, because
the version `1:7.4.33-…` is higher than any `7.4.3-4ubuntu2.x`.

## What `install` does

1. Runs pre-flight checks: root, Ubuntu 20.04, amd64, and `php-fpm7.4 -t` must already pass.
2. Downloads and verifies the `.deb` archive.
3. Saves a backup under `/var/lib/php74-cve-2026/backup-<timestamp>/`:
   - the `/etc/php/7.4` configuration
   - the list of running services
   - the `.deb` of every installed version, taken from the first source that has it:
     1. the apt cache
     2. the repositories (`apt-get download NAME=VERSION`). Ubuntu's `7.4.3-4ubuntu2.29`
        is still in `focal-updates`
     3. `dpkg-repack`, which rebuilds the package from the installed files. The result is
        unsigned and config files go in as they are now

   The source used for each package is printed and recorded in `sources.txt`.
4. Installs the packages with `apt-get install` and keeps the current config files
   (`--force-confold`). `needrestart` is set to only list services; the script restarts
   them itself.
5. Checks the result:
   - `php7.4 -v`
   - `php7.4 -m` must load without warnings
   - the changelog must contain the CVE
   - `php-fpm7.4 -t`, plus `nginx -t` and `apache2ctl -t` when those are running
6. Restarts the services that were running: `php7.4-fpm`, and `apache2` when it is active.
   `nginx` does not embed PHP and is not restarted.
7. **Rolls back automatically** if any of these steps fails.

`uninstall` reinstalls the backed-up `.deb` files with `apt-get install --allow-downgrades`.
Configuration files are not restored automatically; the backup path is printed.

### Network timeouts

| Step | Behaviour |
|---|---|
| Release download (`curl`) | Gives up if no connection is made within 10s, or if the download stalls (below 1 KB/s) for 10s |
| `apt` | `Acquire::http(s)::Timeout=10`, `Acquire::Retries=1` |

| Variable | Default | Purpose |
|---|---|---|
| `PHP74CVE_NET_TIMEOUT` | `10` | Network timeout in seconds |
| `PHP74CVE_RELEASE_URL` | this repo's `v7.4.33-31-focal1` release | Download the archive from a mirror or an internal server instead |

## Behaviour changes

These come from the upstream fix:

- A request that exceeds `memory_limit` (or hits another out-of-memory condition)
  terminates the worker process with `exit(1)` instead of unwinding. PHP-FPM starts a new
  worker. Shutdown functions and destructors do not run for that request.
- The out-of-memory fatal error goes to stderr, not to `error_log`. To see it in the
  PHP-FPM log, set `catch_workers_output = yes` in the pool configuration.
- `session.upload_progress` is disabled.
- Version jump 7.4.3 → 7.4.33: these are bug-fix releases on the same 7.4 branch. Test
  your applications before rolling out widely.

## How the packages were built

1. Downloaded `php7.4_7.4.33-31+ubuntu24.04.1+deb.sury.org+1.dsc` and its sources from
   Launchpad.
2. Verified them:
   - the `.dsc` signature: Ondřej Surý's PPA key `6A1A AD7A E5B4 01C6 E259 A7B2 5706 7BAA 1314 C7FC`
   - the file checksums listed in the `.dsc`
   - `php-7.4.33.tar.xz`: the PHP 7.4 release manager's signature (Derick Rethans), and
     its SHA256 against php.net
3. Built with `dpkg-buildpackage` in a clean `ubuntu:20.04` amd64 container. The only
   change was a `dch` entry for the new version. The source package's patch series includes
   `0164-Avoid-state-corruption-via-bailout.patch`, the CVE fix.

## Testing

Tested in a clean `ubuntu:20.04` container set up like the production server: Ubuntu's
`php7.4 7.4.3-4ubuntu2.29` packages (the same 14 `php7.4-*` packages), the `php-*`
metapackages, and nginx in front of `php7.4-fpm`.

- `install` upgraded all 14 packages to `1:7.4.33-31+ubuntu20.04.1+bagsiz1`
- afterwards:
  - PHP 7.4.33 answers through nginx and every extension loads (curl, gd, mbstring,
    mysqli, pdo_sqlite, xml, zip, bcmath, OPcache)
  - file upload works
  - the changelog contains CVE-2026-109618
  - Ubuntu's `php-*` metapackages are kept, and `apt upgrade` does not replace the
    patched packages
- re-running `install` is a no-op
- `uninstall` returned the server to `7.4.3-4ubuntu2.29`, and the site works again

The tests for each backup source on its own, automatic rollback, tampered packages and
wrong-OS refusal are still running. This section will be updated with their results.

Not covered: real systemd (the container used a stub `systemctl`).

## Disclaimer

**USE AT YOUR OWN RISK.** This project, including the installer script and the packages,
is provided **"AS IS", WITHOUT WARRANTY OF ANY KIND**, express or implied. This includes,
without limitation, warranties of merchantability, fitness for a particular purpose,
security and non-infringement.

- **Not official.** The packages are unofficial rebuilds of Ondřej Surý's source package.
  They are not built, reviewed or supported by Ondřej Surý, Canonical or the PHP project.
- **Your responsibility.** You decide whether to use this software, and you are responsible
  for testing it, for backing up your systems and data, and for any change you make to your
  servers. Running unsupported software (Ubuntu 20.04, PHP 7.4) carries risk that no patch
  removes.
- **No liability.** In no event shall the authors or contributors be liable for any claim,
  damages or other liability arising from, out of, or in connection with this software or
  its use. This covers direct, indirect, incidental, special, consequential or punitive
  damages, data loss, downtime and security incidents, whether in contract, tort or
  otherwise, even if advised of the possibility of such damage.
- **No support obligation.** There is no commitment to support, maintenance, updates or
  security fixes.
- **Not security advice.** Nothing in this repository is professional, security or legal
  advice.
- **No affiliation.** This project is not affiliated with, endorsed by or sponsored by:
  - The PHP Group or the PHP project
  - Ondřej Surý / deb.sury.org
  - Canonical Ltd. or the Ubuntu project
  - GitHub, Inc.

  "PHP", "Ubuntu" and other names are trademarks of their respective owners and are used
  here only to describe compatibility.

## License

- **Installer script and documentation** (`php74-cve.sh`, `README.md`): MIT License, see
  [`LICENSE`](LICENSE).
- **Packages (release assets):** these contain third-party software that stays under its
  original license:
  - PHP is under the [PHP License v3.01](https://www.php.net/license/3_01.txt).
  - Zend Engine is under the Zend Engine License v2.00.
  - Bundled libraries and extensions are under their own licenses.
  - The Debian packaging (`debian/`) is by Ondřej Surý and the Debian PHP maintainers,
    under its own license.

  License texts are included in the packages (`/usr/share/doc/php7.4-common/copyright`).

This product includes PHP software, freely available from <http://www.php.net/software/>.
