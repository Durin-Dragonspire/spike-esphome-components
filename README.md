# SPIKE ESPHome Components

This public repository distributes narrowly scoped ESPHome compiler components
used by SPIKE Home Alarm. It does not contain the SPIKE integration, private
repository history, configuration, credentials, or runtime data.

## Fingerprint Grow

Use immutable release `fingerprint-grow-v2.4.0` from ESPHome:

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/Durin-Dragonspire/spike-esphome-components.git
      ref: fingerprint-grow-v2.4.0
    components:
      - fingerprint_grow
    refresh: never
```

The already-published `fingerprint-grow-v1.0.0`, `fingerprint-grow-v2.0.0`,
`fingerprint-grow-v2.1.0`, `fingerprint-grow-v2.2.0`, and
`fingerprint-grow-v2.3.0` tags remain available for YAML generated against
those releases. Do not move or rewrite published tags.

The release manifest records the component version, component runtime-control
ABI, firmware/Home Assistant handshake version, release tag, and SHA-256 digest
of every distributed file. Those two protocol numbers are separate contracts:
the integration-generated YAML may advance its status handshake without
rewriting this immutable component tag. See `RELEASES.md` before upgrading an
installed reader.

## Repository lifecycle

This repository is a temporary standalone distribution channel while the main
SPIKE Home Alarm repository remains private. When the final public SPIKE Home
Alarm release can host these ESPHome components directly, this repository will
be archived read-only rather than deleted.

Published tags and release files will remain available for existing YAML that
pins an immutable version. New SPIKE releases will point generated YAML to the
canonical component location under SPIKE Home Alarm, and the archive notice
will provide the replacement URL and migration instructions. Do not replace a
pinned component URL until SPIKE publishes that migration guidance.
