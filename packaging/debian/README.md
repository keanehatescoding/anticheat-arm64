# Debian packaging

This directory *is* a `debian/` control directory's contents, kept under
`packaging/debian/` instead of at the repo root so the root doesn't carry
Debian-specific files unconditionally. `dpkg-buildpackage` requires
`debian/` at the top of the source tree it's building, so stage it there
first:

```sh
cp -a packaging/debian debian
dpkg-buildpackage -us -uc -b
```

(`-us -uc`: don't try to GPG-sign the source/changes files, which needs a
key most build machines won't have configured. Drop them to sign a real
release build.) This produces `../hypranticheat_<ver>_arm64.deb` and
`../hypranticheat-dkms_<ver>_arm64.deb` (`.deb`s land in the parent
directory by convention, not `debian/`). Remove the staged `debian/`
directory afterwards (`rm -rf debian`) so it doesn't get committed by
accident.

## Split package

Same split as the AUR package (`packaging/aur/`) and for the same reason
— either half can be reinstalled or rebuilt independently:

- **`hypranticheat`** — the userspace daemon/CLI (`anticheat`), docs, and
  the `/var/lib/anticheat/baselines` state directory.
- **`hypranticheat-dkms`** — the kernel module source, registered with
  DKMS. `hypranticheat-dkms.postinst`/`.prerm` do the same
  dkms-add/build/install + Secure Boot MOK-signing setup as
  `scripts/dkms-install.sh` and the AUR package's `.install` hooks, wired
  into dpkg's `configure`/`remove` maintainer-script actions instead of a
  manual script run. `control` pins `dkms (>= 3.0)` because
  `mok_signing_key`/`mok_certificate`/`framework.conf.d` support — what
  the postinst's `/etc/dkms/framework.conf.d/anticheat.conf` fragment
  relies on — was only added in DKMS 3.0; an older `dkms` would silently
  ignore that fragment and build unsigned.

## Native package, not an archive upload

`debian/source/format` is `3.0 (native)` — there's no separate upstream
tarball, this builds straight from a checkout (or the same GitHub release
tarball the other packaging flavors use, extracted). This is *not*
intended for upload to the actual Debian archive (that has its own much
stricter review process, à la AUR vs. an official Arch repo) — it exists
so `dpkg-buildpackage`/`debuild` produce a working, installable `.deb` for
anyone building locally or hosting their own APT repo, the Debian
equivalent of what `packaging/aur/PKGBUILD` gives Arch users.

## Not yet verified

Unlike the AUR package (built and `namcap`-checked on a real Arch
machine — see `packaging/aur/README.md`), this has **not** been run
through a real `dpkg-buildpackage`/`lintian`/`apt install` cycle — none of
`dpkg-buildpackage`, `debhelper`, or `lintian` were available in the
environment this was authored in. Before relying on this for a real
install, build it and check `lintian ../hypranticheat*.changes` comes back
clean, and run through a real `apt install ../hypranticheat*.deb` /
`apt remove hypranticheat-dkms` cycle on a disposable VM (the DKMS + MOK
setup mutates real system state — `/etc/dkms/`, `/var/lib/dkms/`, the
running kernel's module tree — same reason the AUR README gives for not
testing `pacman -U` on the authoring machine). A container isn't enough
for the full cycle: it shares the host kernel, so it can't actually build
against or load a real kernel module, and has no UEFI to enroll a MOK
into — it only exercises package install/removal and the maintainer
scripts' own logic (the dkms-status parsing, the `--force`/upgrade
handling, the tty-gated MOK messaging), not the DKMS build or Secure Boot
enrollment themselves.
