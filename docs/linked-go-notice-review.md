# Exact linked Go notice coverage

The candidate audit matches each binary's actual linked module path/version to
retained conventional legal text. It does not treat every downloaded module-cache
entry as a linked dependency, and notice presence is not legal approval.

Two recipe gaps were found:

- All eight Go tool recipes omitted the British `LICENCE` spelling. In particular,
  Nuclei's linked `github.com/yassinebenaid/godump@v0.11.1` carries `LICENCE`, not
  `LICENSE`. Both spellings are now retained.
- Gate is built separately and previously retained only its own license, not its
  dependency notices. The Gate builder now retains its exact binary build metadata,
  go.mod/go.sum, Go license and dependency notice archive under
  `/opt/vardrtools/provenance/vardrgate/`, where distribution evidence collection
  can retain them. Its build still verifies module checksums.

The notice archive can contain cache entries not linked into a given binary.
Reviewers must match exact module identities, and may use an exact-version notice
retained elsewhere in the same image. Newly rebuilt image artifacts must confirm
these fixes; a recipe edit alone does not change already built images.

## Unresolved upstream notice

`github.com/censys/censys-sdk-go@v0.19.1`, linked into Nuclei, contains no
conventional LICENSE/LICENCE/COPYING/NOTICE/COPYRIGHT text in its exact official
Go module ZIP. The ZIP matches the build's go.sum. Generated model files named
NoticeReference/UserNotice are API models, not legal notices. Absence is not a
license grant. This remains an explicit review blocker; no license is invented,
no exception is granted, and no dependency is removed by this change.

This fixes notice retention only. It does not claim complete corresponding-source
closure, sublicensing rights, compatibility clearance or release approval.
