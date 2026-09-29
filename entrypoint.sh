#!/bin/sh
# entrypoint.sh — fix ownership of bind-mounted directories then exec tcp-warden.
# Docker creates bind-mount target directories as root:root on the host; this
# script runs as root briefly to chown them before switching to the routewarden
# (uid 1000) user via su-exec or gosu.

set -e

# Fix socket directory ownership for both the container path and any
# bind-mounted variant (/tmp/routewarden on macOS, /var/run/routewarden on Linux)
# If running as root, adjust permissions and optionally drop to non-root user
if [ "$(id -u)" = "0" ]; then
    # Ensure all required state directories exist
    mkdir -p /var/lib/routewarden/plugins /var/lib/routewarden/go /var/lib/routewarden/cache \
             /var/log/routewarden /var/run/routewarden /etc/routewarden /home/routewarden

    # Unconditionally ensure write permissions on all state and source directories
    chmod -R u+rwX /var/lib/routewarden /usr/src/tcp-warden /usr/local/bin /home/routewarden 2>/dev/null || true

    # 0. Restore persistent recompiled binary and sources from volume if previously built
    if [ -f "/var/lib/routewarden/bin/tcp-warden" ]; then
        if /var/lib/routewarden/bin/tcp-warden version >/dev/null 2>&1; then
            cp -f /var/lib/routewarden/bin/tcp-warden /usr/local/bin/tcp-warden
            if [ -f "/var/lib/routewarden/all.go" ]; then
                cp -f /var/lib/routewarden/all.go /usr/src/tcp-warden/plugins/all/all.go
            fi
            if [ -d "/var/lib/routewarden/plugins" ]; then
                for pdir in /var/lib/routewarden/plugins/*; do
                    if [ -d "$pdir" ]; then
                        pname=$(basename "$pdir")
                        mkdir -p "/usr/src/tcp-warden/plugins/$pname"
                        cp -rf "$pdir/"* "/usr/src/tcp-warden/plugins/$pname/" 2>/dev/null || true
                    fi
                done
            fi
        fi
    fi

    # 1. Auto-reintegrate any plugins previously installed and cached in persistent volume (/var/lib/routewarden/plugins)
    if [ -d "/var/lib/routewarden/plugins" ]; then
        for pdir in /var/lib/routewarden/plugins/*; do
            if [ -d "$pdir" ]; then
                pname=$(basename "$pdir")
                if ! /usr/local/bin/tcp-warden plugins list 2>/dev/null | grep -E "^$pname[[:space:]]+" >/dev/null; then
                    echo "🔧 [BOOT] Reintegrating persistent plugin from cache: $pname..."
                    /usr/local/bin/tcp-warden plugins install "$pdir" || true
                fi
                /usr/local/bin/tcp-warden plugins enable "$pname" 2>/dev/null || true
            fi
        done
    fi

    # 2. Auto-install requested plugins if configured via AUTO_INSTALL_PLUGINS
    if [ -n "$AUTO_INSTALL_PLUGINS" ]; then
        for p in $AUTO_INSTALL_PLUGINS; do
            if ! /usr/local/bin/tcp-warden plugins list 2>/dev/null | grep -E "^$p[[:space:]]+" >/dev/null; then
                echo "📦 [BOOT] Installing plugin: $p..."
                if [ -d "/plugins/$p" ]; then
                    /usr/local/bin/tcp-warden plugins install "/plugins/$p" || true
                elif [ -d "/var/lib/routewarden/plugins/$p" ]; then
                    /usr/local/bin/tcp-warden plugins install "/var/lib/routewarden/plugins/$p" || true
                else
                    /usr/local/bin/tcp-warden plugins install "$p" || true
                fi
            fi
            /usr/local/bin/tcp-warden plugins enable "$p" 2>/dev/null || true
        done
    fi

    # Ensure recompiled binary is persisted on volume for instant restart next time
    if [ ! -f "/var/lib/routewarden/bin/tcp-warden" ] || [ "/usr/local/bin/tcp-warden" -nt "/var/lib/routewarden/bin/tcp-warden" ]; then
        mkdir -p /var/lib/routewarden/bin
        cp -f /usr/local/bin/tcp-warden /var/lib/routewarden/bin/tcp-warden 2>/dev/null || true
        if [ -f "/usr/src/tcp-warden/plugins/all/all.go" ]; then
            cp -f /usr/src/tcp-warden/plugins/all/all.go /var/lib/routewarden/all.go 2>/dev/null || true
        fi
    fi

    # Fix ownership for routewarden user across all directories
    for dir in /var/run/routewarden /tmp/routewarden /var/lib/routewarden /var/log/routewarden /usr/src/tcp-warden /usr/local/bin /etc/routewarden /home/routewarden; do
        if [ -d "$dir" ]; then
            chown -R routewarden:routewarden "$dir" 2>/dev/null || true
        fi
    done

    TARGET_USER="${TARGET_USER:-routewarden}"

    # Ensure net_bind_service capability on binary in case it was freshly rebuilt
    setcap 'cap_net_bind_service=+ep' /usr/local/bin/tcp-warden 2>/dev/null || true

    # Run the daemon
    if [ "$TARGET_USER" = "root" ]; then
        exec "$@"
    else
        exec su-exec "$TARGET_USER" "$@"
    fi
else
    # Container already running under a non-root UID
    exec "$@"
fi
