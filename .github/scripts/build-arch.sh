#!/usr/bin/env bash
set -euo pipefail

source /etc/os-release
if [[ ${ID:-} != "arch" ]]; then
  printf 'Container ID does not match arch\n' >&2
  exit 2
fi

root=$(pwd -P)
[[ -f $root/meson.build ]]

pacman -Syu --noconfirm --needed \
  base-devel git glib2 glib2-devel gobject-introspection \
  meson ninja python-cairo python-gobject systemd doctest cairo \
  umockdev opencv openssl pixman libgudev libgusb sudo

if [[ $(id -u) -eq 0 ]]; then
  if ! id builder >/dev/null 2>&1; then
    useradd -m -s /bin/bash builder
    echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder
  fi
fi

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

pkgname=libfprint-fpc1022
cp -a "$root/packaging/arch/"* "$work/"
mkdir -p "$work/archive/$pkgname"
tar -C "$root" --exclude=.git --exclude=artifacts -cf - . |
  tar -C "$work/archive/$pkgname" -xf -
tar -C "$work/archive" -cf "$work/$pkgname.tar" "$pkgname"
rm -rf "$work/archive"
sed -i "s|^source=.*|source=('$pkgname.tar')|" "$work/PKGBUILD"

chown -R builder:builder "$work"

(
  cd "$work"
  sudo -u builder makepkg --config "$work/makepkg-ascii.conf" --noconfirm -s
)

out="$root/artifacts/arch"
mkdir -p "$out"
package=$(find "$work" -maxdepth 1 \
  -name 'libfprint-fpc1022-[0-9]*-x86_64.pkg.tar.*' -print -quit)
[[ -n $package ]]
cp "$package" "$out/"
