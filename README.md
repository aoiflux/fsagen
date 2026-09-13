# File System Artifacts Generator (fsagen)

Deterministic generator for creating diverse file-system artifacts to test forensic tools (Autopsy, EnCase, FTK, etc.). Use YAML manifests for simple operations, playbooks for complex modus operandi simulation, or the bulk generator for a quick synthetic corpus with no YAML required.

## Features

- Deterministic output with `--seed`
- Manifest mode: simple, declarative file operations (create/update/append/delete/mace/rename/copy/truncate/rotate/ads/motw/email/ansible-vault)
- Playbook mode: complex timelines with actors, timed steps, and templating
- Bulk mode: super-simple synthetic corpus generation with `--bulk` and `--depth`
- Author content in real files with `content_file`, shared across scenarios with `--vars-file`
- Real RFC 5322 email: MIME multipart, threading headers, base64 attachments, `.eml` and `.mbox`
- Real PDFs from Markdown, with full control of document metadata
- Real `$ANSIBLE_VAULT;1.1;AES256` files that `ansible-vault` can decrypt
- Extensive file type support: documents, logs, archives, media, emails, Windows artifacts
- MACE (atime/mtime) timestamp control and octal file permissions
- Windows-specific: NTFS ADS and Mark-of-the-Web (MoTW)

## Install

Build from source:

```pwsh
go build -v -o fsagen.exe
```

## Usage

fsagen can generate artifacts using a manifest, a playbook, or the bulk generator:

```pwsh
fsagen [OPTIONS] <output-path>
```

**Options:**
- `--seed N` - PRNG seed for deterministic generation (default: 1)
- `--manifest FILE` - Execute a YAML manifest (simple file operations)
- `--playbook FILE` - Execute a YAML playbook (complex modus operandi)
- `--generate-schema` - Write separate JSON schemas for manifest/playbook and exit
- `--schema-out DIR` - Output directory for `--generate-schema` (default: `examples`)
- `--bulk N` - Super-simple bulk generation: N items per level (no YAML)
- `--depth D` - Bulk generation depth (default: 1)
- `--timeline FILE` - Generate forensic timeline after execution (formats: csv, txt, bodyfile, macb)
- `--vars-file FILE` - YAML map of variables exposed to templates as `${VAR:name}`
- `--var k=v` - Set one template variable (repeatable; overrides `--vars-file`)

**Examples:**

Generate schema file for external input validation:
```pwsh
fsagen --generate-schema
```

This writes:
- `manifest-schema.json`
- `playbook-schema.json`

Generate schema to a custom location:
```pwsh
fsagen --generate-schema --schema-out ./schemas
```

Simple bulk generation with manifest:
```pwsh
fsagen --seed 42 --manifest examples/manifest-bulk-simple.yaml ./output
```

Complex adversary simulation with playbook:
```pwsh
fsagen --seed 100 --playbook examples/playbook-adversary-data-theft.yaml ./crime-scene
```

Generate artifacts with forensic timeline:
```pwsh
fsagen --seed 42 --playbook examples/playbook-comprehensive-ransomware.yaml --timeline timeline.csv ./output
```

Quick synthetic corpus with bulk generator (no YAML):
```pwsh
fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk
```

## Manifest schema

YAML with a sequence of operations:

- action: `create|update|append|truncate|rotate|delete|mace|rename|copy|ads|motw|email|ansible-vault`
- path: target path relative to output root
- type: `file|dir` (for create)
- ext: file extension to append if `path` has no extension
- content: literal content (optional)
- content_file: load content from a file, resolved relative to the manifest (optional)
- content_len: size of deterministic random content (fallback when neither is provided)
- render: run `${...}` substitution over the content. Defaults to `true` for inline
  `content` and `false` for `content_file`, because scripts and PEM keys contain
  `${...}` sequences of their own that must survive verbatim
- mode: octal file permissions, e.g. `"0600"` (default 0644 files, 0755 directories)
- format: `raw` (default) or `pdf`; for the `email` action, `eml` or `mbox`
- pdf: document metadata for `format: pdf` — see below
- email: message definition for the `email` action — see below
- vault: password, vault_id and salt for the `ansible-vault` action
- atime/mtime: RFC3339 timestamps for MACE control
- new_path: new location for `rename`, `rotate` or `copy`
- stream: ADS stream name (for `ads` action, Windows-only)
- zone_id, host_url, referrer_url: for `motw` action (Windows-only)

A manifest may also carry a top-level `variables:` map. Unknown keys are a hard
error: a silently dropped typo produces artifacts that look right and are not.

**Examples:**
- `examples/manifest-basic.yaml` - Basic create/update/delete operations
- `examples/manifest-bulk-simple.yaml` - Quick bulk file generation across multiple types

## Playbook schema

YAML with a timeline and actors:

- **start**: RFC3339 or "now"
- **variables**: Global variables for templating (map of key-value pairs)
- **actors**: List of { name, base, variables }
	- name: Actor identifier
	- base: Base directory for this actor's files
	- variables: Actor-specific variables (override global variables)
- **steps**: Timeline steps
	- actor: Actor name
	- offset: time.Duration from start for first occurrence (e.g., 5m, 2h)
	- every: Repeat interval (optional)
	- repeat: Number of occurrences (default 1)
	- condition: Step-level conditional execution ("odd", "even", "first", "last")
	- batch_count: Generate N files in this step (multiplies actions)
	- actions: List of operations with extras:
		- offset: time.Duration relative to the step occurrence
		- condition: Action-level conditional execution
		- template: Predefined content template ("email", "log", "script", "doc")
		- All standard manifest fields (action, path, content, etc.)

Operations supported: `create|update|append|truncate|rotate|delete|mace|rename|copy|ads|motw|email|ansible-vault` (all operations work in both manifest and playbook). `ads` and `motw` are Windows-only. Timestamps are computed from the timeline unless explicitly provided in the action.

Durations accept `d` and `w` in addition to Go's own units, so a step can be
`offset: 2d6h` rather than `54h`.

**Playbook templating:**
- `${SEQ}` - Monotonic sequence counter
- `${RND:N}` or `${RANDOM:N}` - Deterministic random string of length N
- `${DATE:layout}` - Current time formatted with Go layout (e.g., `${DATE:2006-01-02T15:04:05Z07:00}`)
- `${ACTOR}` - Current actor name
- `${VAR:name}` - Variable substitution (from global or actor-specific variables)
- `${UUID}` - Deterministic UUID based on sequence
- `${IP}` - Deterministic IP address (192.168.x.x range)
- `${HASH:N}` - Deterministic hash-like hex string of length N
- `${BATCH}` - Current batch index (when using batch_count)
- `${ITER}` - Current iteration index (when using repeat)

**Advanced Playbook Features:**

1. **Variables**: Define reusable values at global and actor scope
```yaml
variables:
  campaign_id: "OP-2024-001"
  target_org: "ACME Corp"
actors:
  - name: attacker
    base: users/victim/Downloads
    variables:
      ip_addr: "192.0.2.42"
```

2. **Conditional Execution**: Control when steps/actions run
```yaml
steps:
  - actor: malware
    repeat: 10
    condition: even  # Only runs on even iterations (0, 2, 4, ...)
    actions:
      - action: create
        path: file-${ITER}.txt
        condition: odd  # Further filtering at action level
```

3. **Batch Operations**: Generate multiple files in one step
```yaml
steps:
  - actor: ransomware
    batch_count: 100  # Creates 100 files
    actions:
      - action: create
        path: encrypted-${BATCH}.locked
        content_len: 2048
```

4. **Content Templates**: Use predefined realistic content
```yaml
actions:
  - action: create
    path: message.eml
    template: email  # Generates realistic email structure
```

Available templates: `email`, `log`, `script`, `doc`

**Example playbooks:**

- `examples/playbook-basic.yaml` - Simple two-actor workflow
- `examples/playbook-adversary-data-theft.yaml` - Stages documents, archives, writes exfil logs, backdates
- `examples/playbook-log-tampering.yaml` - Creates baseline logs, injects tampered entries, backdates, deletes
- `examples/playbook-persistence-artifacts.yaml` - Drops startup-like files and .reg exports
- `examples/playbook-email-and-archive.yaml` - Creates emails/images, archives, deletes originals
- `examples/playbook-log-rotate-and-truncate.yaml` - Demonstrates log rotation and truncation
- `examples/playbook-windows-ads-motw.yaml` - Adds NTFS ADS and Mark-of-the-Web (Windows-only)
- `examples/playbook-comprehensive-ransomware.yaml` - **Advanced**: Full ransomware attack with variables, batching, conditions, and templates
- `examples/playbook-insider-threat-exfil.yaml` - **Advanced**: 7-day insider threat scenario with repeated access patterns
- `examples/playbook-malware-lifecycle.yaml` - **Advanced**: 48-hour malware infection lifecycle with beaconing and anti-forensics

## Email, PDF and Ansible vault

### `email` action

Builds a real RFC 5322 message: CRLF throughout, quoted-printable bodies,
base64 attachments, and a MIME shape chosen to fit the content
(`multipart/mixed` wrapping a `multipart/alternative` when there are both
bodies and attachments). Writes a `.eml`, or appends to a `.mbox` with mboxrd
`>From ` escaping.

```yaml
- action: email
  path: Users/priyan/Mail/Inbox/0003.eml
  format: eml                    # or mbox (appends); inferred from the extension
  email:
    from: "Dana Reyes <d.reyes@aperture-talent.example>"
    to: ["Priyan N <priyan.nair@northwindlogistics.example>"]
    cc: ["scheduling@aperture-talent.example"]
    return_path: "bounces+0188@aperture-talent.example"
    subject: "Re: technical assessment"
    date: "2026-02-25T10:05:00+05:30"     # RFC3339; also the default file mtime
    message_id: "<c3f1a97b@aperture-talent.example>"
    in_reply_to: "<b2e0d8f1@northwindlogistics.example>"
    references: ["<CAF9a2c1e@aperture-talent.example>", "<b2e0d8f1@northwindlogistics.example>"]
    headers:                     # an ordered LIST, so Received: can repeat
      - name: Received
        value: "from mx01... ; Wed, 25 Feb 2026 10:05:14 +0530"
      - name: Authentication-Results
        value: "spf=pass; dkim=pass; dmarc=pass"
    body_text_file: content/msg-03.txt
    body_html_file: content/msg-03.html
    attachments:
      - source_file: content/brief.pdf    # relative to the manifest/playbook
        name: "Technical_Assessment_Brief.pdf"
      - source_root: reports/review.pdf   # relative to the output root, for
                                          # attaching an artifact an earlier
                                          # step generated
```

Author-supplied `headers` are emitted first, in order, then the structured
fields — so a `Received:` chain and `Authentication-Results` land where a real
MTA would have written them. A header value that already contains newlines
keeps the author's folding.

MIME boundaries are drawn from the seeded PRNG, so `--seed` reproducibility
holds across the message body too.

### `format: pdf`

Renders a Markdown subset (`#`/`##`/`###` headings, `-` bullets, `|a|b|` tables
with wrapping cells and repeating headers, ``` fenced blocks, `---` rules) into
a paginated PDF, with full control of the document metadata.

```yaml
- action: create
  path: reports/configuration-review.pdf
  format: pdf
  content_file: content/report.md
  render: true
  pdf:
    title: "Configuration Review"
    author: "svc-agent@example.local"
    subject: "Automated assessment"
    keywords: "secrets; review"
    creator: "SentinelIQ Threat Agent 2.1.4"
    producer: "SentinelIQ Report Engine 2.1.4"
    created: "2026-03-14T02:33:12+05:30"   # RFC3339; pin these for
    modified: "2026-03-14T02:33:12+05:30"  # byte-identical output
    page_size: A4                          # A4 (default), A3, A5, Letter
```

Inline markers are **not** interpreted or stripped. A report body carrying
`Wint3r-R0t****-2026` keeps its asterisks; silently rewriting a redaction mask
into something that reads like a real password would be worse than showing a
literal asterisk.

With `created` and `modified` pinned, two renders of the same input produce
byte-identical files. That is what lets one artifact be attached to a message
and land with the same SHA256 as its copy on disk.

### `ansible-vault` action

Produces a genuine `$ANSIBLE_VAULT;1.1;AES256` payload — PBKDF2-HMAC-SHA256
(10,000 iterations), AES-256-CTR, HMAC-SHA256 — that the real `ansible-vault`
decrypts.

```yaml
- action: ansible-vault
  path: infra/group_vars/prod/vault.yml
  content_file: content/vault-plaintext.yml
  mode: "0640"
  vault:
    password: "${VAR:vault_password}"
    vault_id: ""     # non-empty selects the 1.2 header form
    salt: ""         # optional 32-byte hex; pin it for byte-stable output
```

```bash
printf '%s' 'the-password' > /tmp/vpw
ansible-vault view --vault-password-file /tmp/vpw out/infra/group_vars/prod/vault.yml
```

## Sharing values across scenarios

`--vars-file` takes a flat YAML map and exposes every key as `${VAR:name}` in
paths, content and timestamps. One persona file can drive a whole set of
separate manifests, so a hostname or a date is defined once.

```yaml
# personas.yaml
org: "Northwind Logistics"
victim_host: "NWL-WKS-0417"
t_report_generated: "2026-03-14T02:33:12+05:30"
```

```pwsh
fsagen --seed 1414 --vars-file personas.yaml --manifest evidence-02.yaml ./out/02
fsagen --seed 1414 --vars-file personas.yaml --var org="Acme" --manifest evidence-03.yaml ./out/03
```

Precedence is `--var` > `--vars-file` > actor variables > playbook/manifest
variables. An unknown `${VAR:name}` is left verbatim rather than blanked, so a
typo shows up in the output instead of silently emptying a field.

A worked example using all of the above is in
[`ctf/priyan-rogue-agent/`](ctf/priyan-rogue-agent/): six interlocking evidence
items for a CTF scenario.

## Notes on timestamps

- Sets mtime/atime via `os.Chtimes`. ctime is not directly settable on most systems and will reflect metadata change time.
- `mode` is applied before the timestamps, because chmod itself touches ctime.
  Windows honours only the write bit; the field matters on Linux output.
- To emulate directory timestamp skew on deletion, `delete` can include `atime/mtime` which will be applied to the parent directory after removal.

## Reproducibility

- All random values (names, synthetic content) come from a seeded PRNG. Use the same `--seed` to reproduce identical output on the same platform and file system.
- Race-condition free: concurrent operations use proper synchronization while maintaining determinism.

## Supported File Types

The generator can create artifacts with proper structure for:

- **Documents**: .txt, .md, .docx, .pdf
- **Data**: .csv, .json, .jsonl, .xml, .html
- **Logs**: .log, .syslog, .jsonl
- **Media**: .png, .mp4
- **Archives**: .zip
- **Email**: .eml, .mbox
- **Windows**: .reg, .exe, NTFS ADS, MoTW

## Forensic Timeline Generation

After generating artifacts, fsagen can automatically create forensic timelines for analysis:

```pwsh
fsagen --playbook scenario.yaml --timeline output.csv ./artifacts
```

**Timeline Formats:**

- **CSV** (`.csv`): Structured data with all metadata (path, size, mode, timestamps, MD5, type, ADS)
- **TXT** (`.txt`): Human-readable format with detailed file information
- **Bodyfile** (`.bodyfile`): Compatible with The Sleuth Kit's mactime tool
- **MACB** (`.macb`): Modified/Accessed/Changed/Birth timeline showing all timestamp events separately

**Timeline Features:**

- MD5 hash calculation for all files (except files > 100MB)
- Full timestamp capture (access, modify, change/create times)
- NTFS Alternate Data Stream detection (Windows)
- Chronologically sorted by modification time
- Deterministic output (same seed = same timeline)
- **Timeline-only mode**: Generate timelines from existing artifacts without regenerating them

**Example workflows:**

```pwsh
# Generate ransomware scenario with CSV timeline
fsagen --seed 999 --playbook examples/playbook-comprehensive-ransomware.yaml --timeline ransomware.csv ./scene

# Create timeline compatible with mactime
fsagen --playbook examples/playbook-malware-lifecycle.yaml --timeline evidence.bodyfile ./analysis
mactime -b evidence.bodyfile -d > detailed-timeline.txt

# Generate MACB timeline for temporal analysis
fsagen --playbook examples/playbook-insider-threat-exfil.yaml --timeline investigation.macb ./case

# Timeline-only mode: generate timeline from existing artifacts (no regeneration)
fsagen --timeline existing-timeline.csv ./already-generated-folder
```

**Timeline-only mode:**

If you've already generated artifacts but forgot to create a timeline, you can generate one later without regenerating the artifacts:

```pwsh
# Generate timeline from existing folder
fsagen --timeline my-timeline.csv ./existing-artifacts

# Different formats
fsagen --timeline analysis.txt ./crime-scene
fsagen --timeline evidence.bodyfile ./investigation
fsagen --timeline temporal.macb ./case-folder
```

This scans the folder, collects all file metadata, calculates MD5 hashes, and outputs the timeline in your chosen format—no artifact regeneration needed.

See `examples/TIMELINE_EXAMPLES.md` for more timeline generation examples.

## Bulk Generation (no YAML)

Use the bulk generator when you need a fast, synthetic corpus without describing a scenario:

```pwsh
# N items per level, depth D directories deep
fsagen --seed 7 --bulk 3 --depth 2 ./quick-bulk

# You can also emit a timeline for bulk output
fsagen --seed 7 --bulk 3 --depth 2 --timeline timeline.csv ./quick-bulk
```

What it does:
- Creates a directory fan-out up to `--depth` with `--bulk` sub-branches per level
- Populates each level with many file types (txt, docx, png, pdf, mp4, csv, json, xml, html, log, reg, zip, exe, jsonl, syslog, md, eml, mbox)
- Deterministic names and contents from `--seed`

Intended use:
- Quickly produce a sizeable, diverse dataset for tool demos, performance tests, or classroom exercises
- Warm-up data for timeline/report pipelines when a complex MO isn’t needed

Notes:
- Output size grows quickly with `--bulk` and `--depth`. Start small (e.g., `--bulk 2 --depth 1` or `--bulk 3 --depth 2`).
- Bulk mode is structure/content focused; if you need precise timelines, actors, or conditions, prefer Playbooks.
- 

### Related Research Paper
https://link.springer.com/chapter/10.1007/978-981-96-9443-3_17

### Recommended Citation
@InProceedings{10.1007/978-981-96-9443-3_17,
author="Gogia, Gaurav
and Rughani, Parag",
editor="Gohil, Bhavesh N.
and Patel, Sankita J.
and Chaudhary, Naveen Kumar
and Iyengar, S. S.
and Modi, Chirag
and Padhya, Mukti",
title="File System Artefacts Generator (FSAGen): Towards Faster Forensic Tool Testing",
booktitle="Information Security, Privacy and Digital Forensics",
year="2026",
publisher="Springer Nature Singapore",
address="Singapore",
pages="239--248",
abstract="Software testing is one of the most fundamental steps in any software development lifecycle. The larger the scale, the more testing is required to ensure the correctness and reliability of the software. In the case of digital forensics, one of the main problems that researchers face is the availability of datasets for testing the reliability of the product they are evaluating. Different forensic tools with similar features may present different results even with similar inputs. This makes it extremely important to have standardised and reproducible datasets. This research explores synthetic dataset generators and introduces a novel command-line interface (CLI) tool for generating file system artefacts. The tool aims to facilitate the quick and convenient creation of synthetic datasets to aid in the validation of file system forensic tools. By offering a simplified and cross-platform solution, this tool addresses the need for standardised datasets in digital forensics research and enhances the reliability and accuracy of forensic tool evaluations.",
isbn="978-981-96-9443-3"
}
