#!/bin/sh
# entrypoint.sh — fix ownership of bind-mounted directories then exec tcp-warden.
# Docker creates bind-mount target directories as root:root on the host; this
# script runs as root briefly to chown them before switching to the routewarden
# (uid 1000) user via su-exec or gosu.

set -e

# Fix socket directory ownership if it exists and is owned by root
if [ -d "/var/run/routewarden" ] && [ "$(stat -c '%u' /var/run/routewarden)" = "0" ]; then
    chown routewarden:routewarden /var/run/routewarden
fi

# Drop to non-root user and exec the daemon
exec su-exec routewarden "$@"
