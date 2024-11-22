#!/bin/sh
# jenkins build helper script for osmocom-bb.  This is how we build on jenkins.osmocom.org

set -ex

base="$PWD"
deps="$base/deps"
inst="$deps/install"
export deps inst

osmo-clean-workspace.sh

mkdir "$deps" || true

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"
export PATH="$inst/bin:$PATH"

verify_value_string_arrays_are_terminated.py $(find . -name "*.[hc]")

osmo-build-dep.sh libosmocore "" ac_cv_path_DOXYGEN=false
osmo-build-dep.sh libosmo-netif "" ac_cv_path_DOXYGEN=false
osmo-build-dep.sh libosmo-abis "" ac_cv_path_DOXYGEN=false

export PKG_CONFIG_PATH="$inst/lib/pkgconfig:$PKG_CONFIG_PATH"
export LD_LIBRARY_PATH="$inst/lib"

set +x
echo
echo
echo
echo " =============================== osmo-uecups ============================="
echo
set -x

cd "$base"
autoreconf --install --force
./configure --enable-sanitize --enable-external-tests --enable-werror $CONFIG
$MAKE $PARALLEL_MAKE
LD_LIBRARY_PATH="$inst/lib" $MAKE check \
	|| cat-testlogs.sh
LD_LIBRARY_PATH="$inst/lib" \
  DISTCHECK_CONFIGURE_FLAGS="--enable-vty-tests --enable-external-tests --enable-werror $CONFIG" \
  $MAKE distcheck \
  || cat-testlogs.sh

$MAKE maintainer-clean
