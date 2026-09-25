# Native updater patch candidate — 2026-09-25

Raise the macOS Sparkle floor and resolved pin from 2.9.0 to 2.9.6. All other
Swift pins are preserved. The official revision is
`ac2def288cbff5cfc7df3ffef6abdf45b72bcb0a`; SwiftPM verified the published binary
archive checksum
`8d5fb41d960b43f4a68aa14126bf62b098544ec8d191cdcc73eb14e63a8e7606`.

This covers [CVE-2026-47121](https://github.com/sparkle-project/Sparkle/security/advisories/GHSA-hg88-v3cw-3qrh)
and [CVE-2026-47122](https://github.com/sparkle-project/Sparkle/security/advisories/GHSA-g3hp-f6mg-559v),
plus the cumulative symlink/privileged installer fixes in
[2.9.6](https://github.com/sparkle-project/Sparkle/releases/tag/2.9.6).
The delta issue requires malicious update data accepted by signature verification;
the XPC issue requires a local attacker and a narrow interrupted-install window.
It can spoof installation metadata, but does not replace the validated code.
The primary advisory lists 2.9.2 as fixed despite older CVE prose saying no fix.

The application's existing Developer ID signature gate and saved automatic-update
preferences are unchanged. Unsigned development runs use the disabled updater.
No updater installation, signing operation or native release was performed.

Verification:

- The 17 unique pinned Swift revisions now have no OSV commit matches; the old
  Sparkle pin matched the two advisories above. This is an advisory lookup, not
  a complete native source audit.
- SwiftPM resolves the patched framework; its version, archive integrity,
  arm64/x86_64 binaries and packaging/helper paths were independently checked.
- The actual updater protocol/controller declarations extracted from
  `MenuBar.swift` typecheck against the patched framework for macOS 15.
- Full release build with frozen resolution fails in unchanged Peekaboo commit
  `bace59f90bb276f1c6fb613acfda3935ec4a7a90`:
  `ScreenCaptureService.swift:1605` calls `CGWindowListCreateImage`, which the
  current SDK marks unavailable. The dependency pin and that code are unchanged
  by this candidate. Full app tests and a signed update installation are not
  claimed to pass.

Keep this candidate a draft until a separately validated Peekaboo compatibility
repair lets the native build/test gate pass. Do not weaken the updater signature
checks or skip the native CI lane. Rollback is a focused revert of the two
manifest/lock changes; it restores the known vulnerable updater version.
