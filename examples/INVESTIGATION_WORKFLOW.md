# Complete Forensic Investigation Scenario

This example demonstrates the full workflow: generating a sophisticated crime scene and analyzing it with timeline tools.

## Scenario: APT Intrusion with Data Exfiltration

### Step 1: Generate the Crime Scene

```bash
fsagen --seed 12345 \
  --playbook examples/playbook-malware-lifecycle.yaml \
  --timeline apt-timeline.csv \
  ./apt-investigation
```

This creates:
- 48-hour malware infection timeline
- Initial dropper with MoTW
- Persistence mechanisms
- Credential dumps
- Lateral movement artifacts
- Data staging and exfiltration
- Anti-forensics activities
- An observed timeline in CSV format, and beside the output
  (`apt-investigation.fsagen/`) the run manifest, `SHA256SUMS`, the ledger of
  every operation and the answer key of what a tool should find

### Step 2: More Timeline Formats

A tree that exists already gets another timeline without being regenerated
(timeline-only mode):

```bash
fsagen --timeline apt-report.txt ./apt-investigation        # readable report
fsagen --timeline apt-evidence.body ./apt-investigation     # The Sleuth Kit bodyfile
fsagen --timeline apt-macb.macb ./apt-investigation         # MACB events
fsagen --timeline apt-entries.jsonl ./apt-investigation     # JSON lines
```

The ground truth, including the files the scenario deleted, is the modelled
timeline of a second run with the same seed:

```bash
fsagen --seed 12345 --playbook examples/playbook-malware-lifecycle.yaml \
  --timeline apt-intended.body --timeline-source modelled ./apt-reference
```

### Step 3: Analyze with The Sleuth Kit

```bash
# Readable timeline, one line per file and instant
mactime -b apt-evidence.body -z UTC > apt-mactime.txt

# The first three minutes of the infection, as CSV
mactime -b apt-evidence.body -d -y -z UTC 2024-09-01T00:00:00..2024-09-01T00:03:00 > apt-initial-infection.csv
```

### Step 4: Score a Tool

Run the tool under test on `./apt-investigation` (or on an image of it) and
compare what it reports with `apt-investigation.fsagen/answer-key.jsonl`:
every file created, modified, renamed and deleted, every stream, every
timestomp, and every file that ends with its modification time before its
creation time. fsagen's tests read its bodyfile with `mactime`, and it has been
compared by hand with `fls` on ext4 and NTFS images; it has not been tested
with other tools.

### Step 5: Analyze Patterns

Look for forensic indicators in the timeline:

1. **Initial Compromise** (T+0):
   - A PE dropper (imports, version resource, 4 KiB overlay) with a
     Zone.Identifier ADS
   - Unusual file creation in Temp directory

2. **Persistence** (T+2m):
   - Startup folder modifications
   - Registry export artifacts

3. **Credential Harvesting** (T+5m):
   - Multiple creds-*.txt files created
   - Suspicious file creation patterns

4. **Lateral Movement** (T+10m-20m):
   - SMB scan artifacts in Windows/Temp
   - Network enumeration files

5. **Data Staging** (T+45m):
   - Large number of .dat files in staging directory
   - Encrypted chunks with UUIDs

6. **Exfiltration** (T+1h):
   - Large ZIP file creation
   - C2 communication logs

7. **Anti-Forensics** (T+2h):
   - Log truncation
   - File deletions
   - MACE timestamp manipulation

8. **Persistence Verification** (T+24h):
   - Health check files
   - Beacon log updates

9. **Ransomware Deployment** (T+48h):
   - Mass .locked file creation
   - Ransom note appearance

## Expected Timeline Output (CSV Sample)

Observed on Windows (the inode is the file's MFT record number, so it differs
from machine to machine):

```csv
Path,Stream,Type,Size,Mode,UID,GID,Inode,Accessed,Modified,Changed,Born,MD5,Deleted
users/alice/AppData/Local/Temp/wupdmgr32.exe,,file,8704,r/rrwxrwxrwx,0,0,4085524,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,5afe847345ec60a303e2af313e1fff43,
users/alice/AppData/Local/Temp/wupdmgr32.exe,Zone.Identifier,stream,26,r/rrwxrwxrwx,0,0,4085524,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,2024-09-01T00:00:00Z,fbccf14d504b7b2dbcb5a5bda75bd93b,
users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/WindowsUpdate.lnk,,file,256,r/rrwxrwxrwx,0,0,4085579,2024-09-01T00:02:00Z,2024-08-15T10:00:00Z,2024-09-01T00:02:00Z,2024-09-01T00:02:00Z,e3eff4082bc514751e2c3297565cd2d8,
...
```

## Expected MACB Output (Sample)

The timestomped shortcut shows its modification time two weeks before its
birth:

```
Date                                  Size MACB Mode         UID    GID    Inode      Name
2024-08-15 10:00:00.000000000          256 M... r/rrwxrwxrwx 0      0      4085579    /users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/WindowsUpdate.lnk
2024-09-01 00:00:00.000000000         8704 MACB r/rrwxrwxrwx 0      0      4085524    /users/alice/AppData/Local/Temp/wupdmgr32.exe
2024-09-01 00:00:00.000000000           26 MACB r/rrwxrwxrwx 0      0      4085524    /users/alice/AppData/Local/Temp/wupdmgr32.exe:Zone.Identifier
2024-09-01 00:00:30.000000000           54 ...B r/rrwxrwxrwx 0      0      4085538    /users/alice/AppData/Local/Temp/.beacon.log
2024-09-01 00:02:00.000000000          256 .ACB r/rrwxrwxrwx 0      0      4085579    /users/alice/AppData/Roaming/Microsoft/Windows/Start Menu/Programs/Startup/WindowsUpdate.lnk
...
```

## Deterministic Verification

Generate the same scene twice and compare what the determinism contract covers
(an observed timeline differs between runs: inode numbers, and anything that
touched the files afterwards):

```bash
fsagen --seed 12345 --playbook examples/playbook-malware-lifecycle.yaml --timeline t1.body --timeline-source modelled ./scene1
fsagen --seed 12345 --playbook examples/playbook-malware-lifecycle.yaml --timeline t2.body --timeline-source modelled ./scene2

diff t1.body t2.body
diff scene1.fsagen/SHA256SUMS scene2.fsagen/SHA256SUMS
diff scene1.fsagen/answer-key.jsonl scene2.fsagen/answer-key.jsonl
```

No output from the three diffs means the two corpora are the same.

## Use Cases

This workflow is perfect for:

- **Training**: Create realistic scenarios for forensic analysts
- **Tool Testing**: Verify forensic tool capabilities with known datasets
- **Research**: Generate controlled datasets for timeline analysis research
- **Demonstrations**: Show temporal attack patterns in presentations
- **Validation**: Verify forensic tool timeline accuracy
- **Education**: Teach timeline analysis with reproducible examples
