### Added
 * The Linux release builds include CycloneDX SBOMs in `sbom/`, one for the
   `nabto_device` and `nm_iam` libraries and one for `tcp_tunnel_device`. They
   list the third party components with the versions the build actually used,
   including musl and the GCC runtime which are statically linked into the
   executable.
