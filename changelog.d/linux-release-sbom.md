### Added
 * The Linux release assets include a CycloneDX SBOM for each executable,
   `tcp_tunnel_device_<target>.cdx.json` and
   `thermostat_device_<target>.cdx.json`. They list the components linked into
   the executable with the versions the build actually used, including musl and
   the GCC runtime.
