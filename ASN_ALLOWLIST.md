# ASN allowlisting

ASN lookup uses a local JSON routing snapshot, loaded and validated at startup.
No DNS or HTTP request is made while handling traffic. Configure ASN identifiers
as strings, either `"64500"` or `"AS64500"` (case insensitive). Both IPv4 and IPv6
are supported, including IPv4-mapped client addresses.

## Build the routing snapshot

Convert locally downloaded GeoLite2/GeoIP2 ASN Blocks CSV files with Python 3:

```sh
python3 scripts/build-asn-db.py -o /etc/routewarden/asn.json \
  GeoLite2-ASN-Blocks-IPv4.csv GeoLite2-ASN-Blocks-IPv6.csv
```

The database format is an object mapping ASN identifiers to CIDR arrays. This
illustrative data uses documentation ASNs and addresses:

```json
{
  "64500": ["192.0.2.0/24", "2001:db8::/32"],
  "64501": ["2001:db8:1::/48"]
}
```

Keep routes for other ASNs in the snapshot: longest-prefix matching ensures a
more specific route owned by another ASN does not inherit an allowed parent's
bypass. Conflicting origins for the same prefix are rejected. Unknown addresses
never match. Invalid identifiers, unreadable or malformed databases, and allowed
ASNs with no routes prevent initialization. Empty allowlists disable this feature.

The snapshot is held in memory. Replace the file and recreate the middleware instance or fully restart the
daemon to refresh routing data; existing instances keep their original snapshot.
The CLI proxy reload endpoint does not refresh ASN policy or routing data.
Paths are resolved by the process, so mount the file into each proxy container.

## TCP/UDP configuration and behavior

```yaml
global:
  asn_db: /etc/routewarden/asn.json
  allowed_asns: ["64500"]
services:
  app:
    listen: ":8443"
    upstream: "127.0.0.1:9443"
    protocol: tcp
    transport: both
    allowed_asns: ["64501"]
```

A nonempty service allowlist replaces the global ASN allowlist, matching existing
IP allowlist inheritance. An empty service list inherits the global list. With
an effective ASN allowlist, unknown origins (including private addresses absent
from the snapshot) and nonmatches are rejected with `asn_denied` in security events.
Matching an ASN does not bypass bans, CrowdSec, IP filters, country filters,
rate limits, or protocol inspection. The same admission rules apply to TCP and UDP.
