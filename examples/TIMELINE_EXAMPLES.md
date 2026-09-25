# Timeline examples

Generate a scenario and write a timeline of it in one command. The timeline file
must lie outside the output directory. See README.md, *Forensic Timeline
Generation*, for what each format holds.

## Formats

The format comes from the extension, or from `--timeline-format`:

```bash
fsagen --seed 42 --playbook playbook-basic.yaml --timeline timeline.csv ./output      # CSV
fsagen --seed 42 --playbook playbook-basic.yaml --timeline report.txt ./output2       # text
fsagen --seed 42 --playbook playbook-basic.yaml --timeline evidence.body ./output3    # TSK bodyfile
fsagen --seed 42 --playbook playbook-basic.yaml --timeline events.macb ./output4      # MACB
fsagen --seed 42 --playbook playbook-basic.yaml --timeline entries.jsonl ./output5    # JSON lines
```

A second timeline of a tree that already exists does not regenerate it
(timeline-only mode, always observed):

```bash
fsagen --timeline report.txt ./output
fsagen --timeline evidence.body ./output
```

## Observed and modelled

The default timeline is read back from disk. A modelled timeline is what the
scenario intends, and includes the files it deleted:

```bash
fsagen --seed 12345 --playbook playbook-malware-lifecycle.yaml \
  --timeline intended.body --timeline-source modelled ./scene
grep deleted intended.body
```

```
ace5141c8952f9c46b6c174b58f3c2da|/users/alice/AppData/Local/Temp/creds-0.txt (deleted)|16|r/rrw-r--r--|0|0|126|1725149100|1725149100|1725149100|1725149100
```

(Times the platform cannot set are 0 there: on Linux, the change and creation
columns.)

## With The Sleuth Kit

```bash
fsagen --seed 999 --playbook playbook-comprehensive-ransomware.yaml --timeline ransomware.body ./ransomware-scene
mactime -b ransomware.body -d -y -z UTC > ransomware-mactime.csv
```

`mactime` accepts fsagen's bodyfile (`TestMactimeAccepts`); an unknown time
(written 0) shows as `0000-00-00T00:00:00Z`.

## Comparing runs

An observed timeline differs between two runs (inode numbers, and anything
that touched the files afterwards). To check that two runs produced the same
corpus, compare what the determinism contract covers:

```bash
fsagen --seed 7 --playbook playbook-basic.yaml --timeline a.body --timeline-source modelled ./a
fsagen --seed 7 --playbook playbook-basic.yaml --timeline b.body --timeline-source modelled ./b
diff a.body b.body
diff a.fsagen/SHA256SUMS b.fsagen/SHA256SUMS
diff a.fsagen/answer-key.jsonl b.fsagen/answer-key.jsonl
```
