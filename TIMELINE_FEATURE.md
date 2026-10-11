# Timelines: design notes

How fsagen's `--timeline` works, and why. The user-facing description is in
README.md (*Forensic timelines*); examples are in
`examples/TIMELINE_EXAMPLES.md`.

## Two sources

| | observed (default) | modelled (`--timeline-source modelled`) |
|---|---|---|
| Built from | the output tree, or the finished image, read back after the run | the run's model and ledger; reads nothing from disk |
| Deleted objects | never (they are gone) | listed, `name (deleted)`, with the times they had when deleted |
| Inode column | NTFS MFT record number, Unix inode number | the ledger's object number |
| Mode | as the file system reports it (on Windows, written as TSK does for NTFS) | the mode fsagen requests, before any umask |
| Directory size | as the file system reports it (0 on Windows) | 0 |
| Times | the four times the platform reports | the scenario's times, where the run can set them; unknown otherwise |
| MD5 | read from disk (quiet handles; `--hash-limit` caps it) | the ledger's |
| Deterministic | no | yes, byte for byte, for the same inputs and capability set |
| Available | always, including timeline-only mode | after a manifest or playbook run |

The observed timeline is what a forensic tool would see; the modelled one is
the ground truth to compare it with. Where the run controls a time, the two
agree (`TestModelledMatchesObserved`).

## Entries

`timeline.Entry` has a path (slash-separated, relative to the root), a type
(`file`, `dir`, `link`, `stream`, `other`), a stream name for streams, mode,
size, UID, GID, inode, four times (access, modification, metadata change,
birth) each of which may be unknown (zero), an MD5 ("" when not computed), a
deleted flag, a link's target, a file's link count, and a `$FILE_NAME` flag.

A named stream is an entry of its own, carrying its file's times, as NTFS keeps
them per file and as The Sleuth Kit lists them. So is a name's NTFS
`$FILE_NAME`, carrying that attribute's times, where the run sets them (an
NTFS image): `path ($FILE_NAME)` in the bodyfile, MACB and text formats, the
type `filename` in CSV, `"file_name": true` in JSON lines. The root is not an
entry.

## Where each time comes from

| Platform | Access, modification, change | Birth | Package |
|---|---|---|---|
| Windows | `GetFileInformationByHandleEx(FileBasicInfo)` on a handle opened relative to the parent, itself opened through the root | same call (`CreationTime`) | `sandbox/times_windows.go` |
| Linux | `statx` relative to the parent directory's descriptor, not following a final link | `statx` when it sets `STATX_BTIME`, else unknown | `sandbox/times_linux.go` |
| macOS, FreeBSD, NetBSD | `lstat` through the root | `Birthtimespec` when not negative | `sandbox/times_bsd.go` |
| A disk image | the image's own reader, over libfat, libext or libntfs (FAT keeps no change time) | the same reader | `volume/` |

The macOS and FreeBSD builds are compiled and vetted by the gate, never run;
NetBSD is not built.

No time is ever copied into another's column. The file ID comes from
`FileIdInfo` on Windows (the low 48 bits of the file reference on NTFS: the MFT
record number) and from the inode number on Unix.

## Reading without changing what is read

Every directory listing and every digest goes through a handle on which access
time updates are suspended: `SetFileTime` with an access time of all ones on
Windows (for files, directories and named streams), `O_NOATIME` on Linux when
the caller owns the file. Metadata is read with calls that do not touch access
times. On a live volume the walk goes through the sandbox, so it cannot leave
the root; on an image it goes through the image's reader (`timeline.GenerateFrom`
takes any `target.Reader`), which touches nothing.

Anything the walk cannot read (a directory it cannot list, a file another
process holds open without sharing) is an error that names the path. The
timeline is built completely in memory before its file is written.

## Formats

All six are written from the same entries (`timeline/formats.go`):

- `bodyfile`: TSK bodyfile 3.x. A name containing `|` or a line break cannot
  be written in it, and is an error.
- `macb`: one line per entry and distinct instant, flags `MACB` for the times
  that fall then; unknown times have no line.
- `csv`, `jsonl`: every field; unknown times empty (CSV) or absent (JSON).
- `timesketch`: one Timesketch event per entry and known time, with Plaso's
  `timestamp_desc` names and microsecond times; chosen by name only, since
  `.jsonl` already means `jsonl`.
- `txt`: one block per entry.

The text formats (`txt`, `macb`) start with a line saying which source they
are; the run manifest records the source, format and file name of every
timeline written after a run, and the SHA-256 of a modelled one.

## Tests

`timeline/timeline_test.go` (formats, goldens in `timeline/testdata`, the
strict bodyfile parser, `mactime` where installed, walk errors, quiet reads,
streams, the change/birth split), `manifest/timeline_test.go` (the modelled
timeline and answer key from real runs, including
`TestModelledMatchesObserved`), `sandbox/times_linux_test.go` (statx birth
times), and the goldens of every example's modelled bodyfile under
`testdata/golden/v<generator version>/<os>/bodyfile`. `docs/testing.md` maps
each timeline finding in the audit brief to the test that closes it.

## Known limits

- Directory sizes on Windows are 0: Windows reports none through the calls
  fsagen uses. The Sleuth Kit reads the size of the directory index instead.
- Times in the bodyfile are whole seconds, as in TSK's format; the other
  formats keep fractions.
- On a live volume, NTFS `$FILE_NAME` times are never read or set; TSK's
  `fls` lists them as separate `($FILE_NAME)` records. An NTFS image sets and
  reads them.
- An observed timeline shows whatever else happened to the output after the
  run: Windows Search adds an `OECustomProperty` stream to `.eml` files in
  indexed folders, and anything that reads a file may move its access time.
