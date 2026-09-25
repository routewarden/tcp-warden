package all

import (
	// Standard modular plugins
	_ "github.com/routewarden/tcp-warden/plugins/ftp"
	_ "github.com/routewarden/tcp-warden/plugins/mysql"
	_ "github.com/routewarden/tcp-warden/plugins/postgres"
	_ "github.com/routewarden/tcp-warden/plugins/redis"
	_ "github.com/routewarden/tcp-warden/plugins/tls_sni"

	// Example third-party custom plugins
	_ "github.com/routewarden/tcp-warden/plugins/examples/echo_filter"
	_ "github.com/routewarden/tcp-warden/plugins/examples/mqtt"
)
