# Workshop datasets

Three playbooks, one per hands-on exercise, each built into an NTFS disk image.
Every name in them is a role or a reserved placeholder: the domains are
`.example` and `.test`, and the companies are Example Corp and Vendor A to E.

| Playbook | Exercise | Seed |
|---|---|---|
| [timestomp.playbook.yaml](timestomp.playbook.yaml) | Detecting timestomping: `$STANDARD_INFORMATION` against `$FILE_NAME` | 2902 |
| [malvertising.playbook.yaml](malvertising.playbook.yaml) | Malware delivered through ads: a redirect chain, its cookies, and the download's Mark-of-the-Web | 3303 |
| [registry-persistence.playbook.yaml](registry-persistence.playbook.yaml) | Malicious registry entries: Run, RunOnce and a service, among ordinary ones | 4404 |

Each file's header says what a learner should find and which items are decoys.

## Build

Run these from the repository root. They need fsagen v0.4.0 or later, which
added the malvertising history's redirect hops and its cookie jar, the
timestomp image's third clock and the change journal. Any release at generator
version 8 gives the same image bytes for the same command, on every platform.

```sh
fsagen --seed 2902 --playbook workshops/timestomp.playbook.yaml \
  --image timestomp.img --image-fs ntfs --image-size 64M \
  --image-time 2026-03-12T06:00:00Z \
  --timeline timestomp.body --timeline-source modelled

fsagen --seed 3303 --playbook workshops/malvertising.playbook.yaml \
  --image malvertising.img --image-fs ntfs --image-size 64M \
  --image-time 2026-03-12T06:00:00Z \
  --timeline malvertising.body --timeline-source modelled

fsagen --seed 4404 --playbook workshops/registry-persistence.playbook.yaml \
  --image registry-persistence.img --image-fs ntfs --image-size 64M \
  --image-time 2026-03-12T06:00:00Z \
  --timeline registry-persistence.body --timeline-source modelled
```

Each run writes the following:
- **The image:** a raw disk with an MBR and one NTFS partition starting at
  sector 2048.
- **A modelled bodyfile.**
- **`<image>.fsagen/`:** the run's records. `answer-key.jsonl` holds every
  planted fact, with its ATT&CK technique where the playbook tags one.

For a disk laid out as a Windows system disk, add `--partition gpt` and give
it room (`--image-size 128M`): the NTFS volume is then the third of four
partitions, after the EFI system and Microsoft reserved partitions and
before recovery, and learners find it with `mmls` rather than assume sector
2048. The checks below then take its start from `mmls` in place of `2048`.

The same seed, playbook and fsagen version give the same bytes on every
platform. `run-manifest.json` records the image's SHA-256, so you can compare
yours against it.

**Executables stay inside the images.** The timestomp and malvertising images
each hold a generated PE. Windows Defender has flagged generated PEs before,
with verdicts that change from run to run. If you extract the files onto a
Windows disk, add a Defender exclusion for that folder first. The registry
playbook writes no executable, so it can also be built into a plain directory
and shared as one:

```sh
fsagen --seed 4404 --playbook workshops/registry-persistence.playbook.yaml ./registry
```

## Check it

The checks below use tools that share no code with fsagen.
`TestWorkshopTimestomp`, `TestWorkshopMalvertising` and
`TestWorkshopRegistryPersistence` repeat the essentials on every test run,
reading each image through libntfs and SQLite.

**Timestomping, with The Sleuth Kit:**

```sh
fls -r -p -o 2048 timestomp.img | grep sync-helper.exe       # its inode
istat -o 2048 timestomp.img <inode>
```

The `$STANDARD_INFORMATION` "Created" time is 2025-11-04 10:12:00.000000000.
The `$FILE_NAME` "Created" time is 2026-03-11 09:20, with a fraction of a
second. The `$STANDARD_INFORMATION` "MFT Modified" time is 09:21, when the
times were set. `collect.zip` and `policy-2023.txt` both show a modification
time before their creation, but their two creation times agree.

The change journal tells the same story from outside the file's record:

```sh
fls -o 2048 timestomp.img 11 | grep UsnJrnl                  # $Extend's entries
usnjls -o 2048 timestomp.img 27 | grep -E 'sync-helper|collect'
```

`$UsnJrnl` is record 27. `usnjls` prints times as Unix seconds; `-l` prints
each record in full. `sync-helper.exe` has a `FILE_CREATE` record at 09:20
and a `BASIC_INFO_CHANGE` at 09:21; `collect.zip` one at 09:45. The images of all
three exercises keep the journal; `--no-usn-journal` builds one without it.

**Malvertising, with The Sleuth Kit and SQLite:**

```sh
fls -r -p -o 2048 malvertising.img | grep -E 'History|Cookies|CodecUpdate'
icat -o 2048 malvertising.img <History inode> > History
icat -o 2048 malvertising.img <Cookies inode> > Cookies
istat -o 2048 malvertising.img <CodecUpdate inode>           # find the Zone.Identifier attribute id
icat -o 2048 malvertising.img <inode>-128-<id>               # the Mark-of-the-Web
sqlite3 History "SELECT v.id, v.from_visit, printf('0x%08x', v.transition), u.url
                 FROM visits v JOIN urls u ON u.id = v.url ORDER BY v.id"
sqlite3 Cookies "SELECT host_key, name, expires_utc FROM cookies"
```

Two hops carry the server-redirect bit, `0x80000000`. `px.tracker.test` holds
a cookie, and the history never visited it. The Mark-of-the-Web has
`ZoneId=3`, and its `HostUrl` is the CDN URL the download's
`downloads_url_chains` ends at.

**Registry, with Windows' own parsers** (no administrator rights needed):
extract `NTUSER.DAT`, `SOFTWARE`, `SYSTEM`, `System.evtx` and `Security.evtx`
with `icat` as above. Then:

```powershell
Get-WinEvent -Path .\System.evtx   -Oldest | Format-List TimeCreated, Id, Message
Get-WinEvent -Path .\Security.evtx -Oldest | Format-List TimeCreated, Id, Message
```

A hive can be opened without loading it into the machine's registry with
`RegLoadAppKey`, or with any offline hive viewer. Things to look at:
- `NTUSER.DAT` key `Software\Microsoft\Windows\CurrentVersion\Run`: the
  `SyncAgent` value, and the key's last-write time of 09:22.
- `SOFTWARE` key `Microsoft\Windows\CurrentVersion\RunOnce`: `CacheRebuild`.
- `SYSTEM` key `ControlSet001\Services\UpdateBroker`.
