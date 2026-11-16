#!/bin/sh
# DOCKER-OVERLAY2 (2026-11-16): put the hosted runner's Docker back on the
# overlay2 graph driver. Run it as the first step after checkout in every
# hosted job that runs Docker in its steps.
#
# Why: the ubuntu-24.04 image shipped Docker 28.0.4 on overlay2. The
# ubuntu-26.04 image ships Docker 29.4.2 with no /etc/docker/daemon.json, and
# Docker 29 defaults a fresh install to the containerd image store (`docker
# info`: Storage Driver overlayfs, io.containerd.snapshotter.v1). That store
# keeps compressed and uncompressed layers and adds unpack work to every
# build, load and container start; measured 1.3-2.8x slower on the same
# hardware (runner-images #14226; the cross-repo note
# DOCKER-UBUNTU-2604-OVERLAY2.md). `features["containerd-snapshotter"] = false`
# selects the graph driver explicitly, even on a fresh install (moby
# docker-v29.4.2, daemon/image_store_choice.go lines 115-122).
#
# Never run it where the daemon is shared or already in use: it restarts
# dockerd, which stops every running container. That rules out a local
# machine, job containers, and any job with `services:` (the service
# containers start before the first step and would die here). Images already
# in the containerd store are no longer visible afterwards; the job builds or
# pulls what it needs.
#
# The last line fails the job if the switch ever stops taking effect.
set -eu
conf=/etc/docker/daemon.json; tmp=$(mktemp)
if [ -s "$conf" ]; then sudo cat "$conf" >"$tmp"; jq -e 'type=="object"' "$tmp" >/dev/null; else echo '{}' >"$tmp"; fi
jq '.features = ((.features // {}) + {"containerd-snapshotter": false})' "$tmp" >"$tmp.new"
sudo install -m 0644 "$tmp.new" "$conf"
sudo systemctl restart docker
i=0; until docker info >/dev/null 2>&1; do i=$((i+1)); [ $i -le 60 ] || exit 1; sleep 1; done
[ "$(docker info --format '{{.Driver}}')" = overlay2 ] || { echo "storage driver is not overlay2" >&2; exit 1; }
echo "docker storage driver: overlay2"
