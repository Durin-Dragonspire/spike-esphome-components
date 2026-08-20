# SPIKE ESPHome Components

This public repository distributes narrowly scoped ESPHome compiler components
used by SPIKE Home Alarm. It does not contain the SPIKE integration, private
repository history, configuration, credentials, or runtime data.

## Fingerprint Grow

Use immutable release `fingerprint-grow-v1.0.0` from ESPHome:

```yaml
external_components:
  - source:
      type: git
      url: https://github.com/Durin-Dragonspire/spike-esphome-components.git
      ref: fingerprint-grow-v1.0.0
    components:
      - fingerprint_grow
    refresh: never
```

The release manifest records the component version, protocol version, release
tag, and SHA-256 digest of every distributed file. See `RELEASES.md` before
upgrading an installed reader.

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
