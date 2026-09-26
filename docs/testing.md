# What each finding is tested by

`plan.json` is the audit brief the Mutant QUILLDROP workshop wrote against
fsagen at 62d759c, after four of its six exercises broke on output that was
silently not what the scenario asked for. This document exists because one
of those findings (F-PLAT-6) was that the code had almost no tests: every
finding is listed with the test that fails if its fix is undone, and the
few that no test can close say so plainly.

Each phase's entry in `CHANGELOG.md` carries the mutation run behind these
names: the patch applied to the source, the test that noticed, and the
restore. A name here without such a row is one a gate step or a document
closes instead. `TestDocumentedTestsExist` checks that every name in this
file and in the README is a test that still exists.

## Safety

| Finding | What it was | Verified by |
|---|---|---|
| F-SEC-1 | Paths escape the output root | `TestPathRules`, `TestNothingWrittenOutsideRoot` |
| F-SEC-2 | A ':' in a path silently creates an NTFS alternate data stream | `TestPathRules` |
| F-SEC-3 | An output path that names an existing file generates into that file's parent directory | `TestOutputIsFileRefused` |
| F-SEC-4 | Every file is created with os.ModePerm (0777) | `TestFileModeIsApplied`, `TestDirAndRotateModesAreApplied`, `TestDefaultFileModeIsNot0777`; these three run on Linux only; on Windows they skip, because the platform keeps no mode bits |
| F-SEC-5 | Generating into a non-empty directory merges with whatever is already there | `TestNonEmptyRootNeedsCleanOrIntoExisting` |

## Input validation

| Finding | What it was | Verified by |
|---|---|---|
| F-IN-1 | YAML decoding ignores unknown keys | `TestUnknownKeyPerStruct` |
| F-IN-2 | Invalid timestamps are silently ignored | `TestBadTimeIsError` |
| F-IN-3 | An invalid action offset is silently ignored | `TestDurations` |
| F-IN-4 | An unknown condition evaluates to true | `TestUnknownCondition` |
| F-IN-5 | An undefined ${VAR:name} is left in the output literally | `TestUndefinedVariableIsError` |
| F-IN-6 | 'template' silently overrides 'content'; an unknown template silently becomes 256 random characters | `TestTemplateRules` |
| F-IN-7 | Deleting a path that does not exist succeeds silently | `TestDeleteMissing` |
| F-IN-9 | Out-of-range zone_id is silently coerced to 3 | `TestValueRules` |
| F-IN-10 | ads and motw on a missing path silently create an empty base file | `TestPreconditions` |
| F-IN-11 | 'update' on a missing file creates it (and fails if its directory is missing) | `TestUpdateMissingIsError` |
| F-IN-12 | A trailing '/' means 'directory' only on Unix | `TestPathRules` |
| F-IN-13 | The JSON Schemas are advisory and partly wrong | `TestSchemaDrift`, `TestSchemaAllowsExactlyTheFieldMatrix`, `TestSchemaRootKeysMatchSpec`, `TestDryRunGoldens`, `TestValidateAndDryRunWriteNothing`; the schema is generated from the field matrix the compiler validates against, so it cannot drift |

## Input model

| Finding | What it was | Verified by |
|---|---|---|
| F-IN-8 | A later action cannot refer to a file an earlier action generated | `TestAttachmentRefNamingSeveralFiles`, `TestRefsDeleteAllStaging` |
| F-IN-14 | Playbook mode does not template stream, host_url, referrer_url or explicit atime/mtime; manifest mode does | `TestEveryStringFieldRenders` |
| F-IN-15 | Operations execute in declaration order, not scenario-time order | `TestPlaybookRunsInTimeOrder` |
| F-IN-16 | repeat without every stacks every occurrence on the same instant, without comment | `TestRepeatWithoutEvery` |

## Determinism

| Finding | What it was | Verified by |
|---|---|---|
| F-DET-1 | Bulk mode is not deterministic | `TestBulkDeterministic` |
| F-DET-2 | Bulk mode exits while generators are still writing (19 waited for, 20 launched) | `TestBulkNoJournalExactCounts`, `TestBulkErrorReturnedNoLeak` |
| F-DET-3 | Wall-clock time leaks into generated content | `TestNoWallClockInContent`, `TestStartNowFlagged` |
| F-DET-4 | Timeline files are never reproducible | `TestModelledTimelineIdenticalAcrossRuns`, `TestTimelineZoneIndependent`, `TestNoWallClockInTimeline` |
| F-DET-5 | One global PRNG stream: editing one action changes unrelated files | `TestInsertingUnrelatedActionLeavesOtherFilesUnchanged`, `TestTokenDrawIndependentOfOtherFields`, `TestPRNGGoldenVectors`, `TestExampleContentGoldens` |
| F-DET-6 | Docs promise determinism the code does not deliver | `TestDeterminismHarness`; the finding asked for the contract to be stated: it is the README section *Determinism contract*, and the harness holds the tool to it |

## Timestamp fidelity

| Finding | What it was | Verified by |
|---|---|---|
| F-TIME-1 | Creation time is never set, so every scenario file is born after it was modified | `TestCreateSetsCreationTime` |
| F-TIME-2 | 'mace' sets two of the four times | `TestChangeTimeSticks`, `TestMaceSetsFourTimes` |
| F-TIME-3 | Later writes silently overwrite times set earlier | `TestAdsAndMotwKeepTimes`, `TestDirTimesFollowLastChildEvent` |
| F-TIME-4 | Writing the timeline changes the evidence it describes | `TestTimelinePassKeepsAtime`, `TestOpenQuietKeepsAtime`, `TestReadDirQuietKeepsAtime` |
| F-TIME-5 | All scenario times fall on whole seconds | `TestNanoPrecisionRoundTrip`, `TestJitterDeterministicAndNeverOnExplicit` |

## Timestamp fidelity (design limit)

| Finding | What it was | Verified by |
|---|---|---|
| F-TIME-6 | A live-filesystem generator cannot control NTFS $FILE_NAME times | `TestRunManifestTimeCapabilities` |

## Timeline

| Finding | What it was | Verified by |
|---|---|---|
| F-TL-1 | An unrecognised --timeline extension silently writes CSV | `TestTimelineFormats` |
| F-TL-2 | The bodyfile writes the same value for ctime and crtime, and that value means different things per OS | `TestBodyfileCrtimeNotCtime`, `TestLinuxBtimeFromStatxOrZero`, `TestBodyfileGolden` |
| F-TL-4 | ADS detection only checks three hard-coded names | `TestStreamsQuillAndSpaceNameWithSizes` |
| F-TL-6 | The bodyfile does not follow Sleuth Kit conventions | `TestBodyfileGolden`, `TestBodyfileStrictParserRoundTrip`, `TestUnsafeNameRefused`, `TestHashLimit` |
| F-TL-7 | The MACB writer is not a MACB timeline | `TestMACBSixteenCombinations` |
| F-TL-9 | Ties in the mtime sort have no defined order | `TestTimelineTieOrder` |

## Platform

| Finding | What it was | Verified by |
|---|---|---|
| F-TL-3 | fsagen does not compile for macOS or FreeBSD | the gate cross-builds darwin and freebsd on amd64 and arm64 on every change; no test has ever run on either, and the README says so |
| F-PLAT-2 | On Linux and macOS a playbook aborts at its first ads or motw action | `TestExplicitCrtimeUnsupportedPreflight`, `TestDroppedTimeFieldRecorded`, `TestUnsupportedOpsFailBeforeAnyWrite` |
| F-PLAT-8 | Windows path hazards are not checked | `TestPortability`, `TestFoldCollision` |

## Timeline / ground truth

| Finding | What it was | Verified by |
|---|---|---|
| F-TL-5 | Deleted files leave no trace in any output | `TestModelledBodyfileMarksDeleted`, `TestDefaultCrtimeRecordedUncontrolled` |

## Timeline / CLI

| Finding | What it was | Verified by |
|---|---|---|
| F-TL-8 | Timeline failures are hidden | `TestWalkErrorReported`, `TestTimelineFailures` |

## Content

| Finding | What it was | Verified by |
|---|---|---|
| F-GEN-1 | content_len ignores the file type: an .exe is not a PE, a .zip is not a zip | `TestZipIsReadableWithSizesInPlace`, `TestStoredZipOverheadIsExact`, `TestZipRefusesDuplicateAndAbsoluteNames`, `TestPNGDecodesAndCarriesPadding`, `TestJPEGDecodesAndCarriesPadding`, `TestTypedExtensionInfersOrRefuses`, `TestTypedFormatsParse` |
| F-GEN-2 | There is no way to build an archive from other generated files | `TestArchiveMembersMatchSources`, `TestArchiveBaseMustCoverEveryMember`, `TestArchiveRefusesEmptyPattern` |
| F-GEN-3 | The generated .exe is a 256-byte DOS stub, not a PE | `TestPEHeaderFieldsEqualInputs`, `TestPEChecksumMatchesWindows`, `TestPEChecksumCoversTheWholeImage`, `TestTypedFormatsParse` |
| F-GEN-4 | The generated .mp4 is text | `TestMP4HasFtypMoovMdat`, `TestMP4DurationAndDimensions` |
| F-GEN-5 | Browser history databases use the wrong epochs and are only reachable from bulk mode | `TestChromeWebKitEpoch`, `TestFirefoxPRTime`, `TestStandardHistorySQLReturnsVisits` |
| F-GEN-6 | PNG and MP4 generators continue after an error and send several results | `TestPngMp4UnwritableDirOneError` |
| F-GEN-7 | The email template is not a real email | `TestMailTemplateIsRFC5322` |
| F-GEN-8 | Random content is base32 text only | `TestFillerKinds`, `TestContentKindShapesTheBytes` |
| F-GEN-9 | No in-place edit: a log cannot lose lines | `TestEditDeleteLines40to60`, `TestEditRefusesMissingLines`, `TestEditReplaceAndInsert` |
| F-GEN-10 | Bulk text-log generators hard-code 2021 dates | `TestManifestDateNeedsTime` |

## Dependencies

| Finding | What it was | Verified by |
|---|---|---|
| F-GEN-11 | Unmaintained or heavyweight dependencies | the gate runs `go mod tidy -diff`; the README says what each of the five direct dependencies is for |

## Packaging

| Finding | What it was | Verified by |
|---|---|---|
| F-PLAT-1 | 'go install github.com/aoiflux/fsagen@latest' fails | no test: `go install github.com/aoiflux/fsagen@latest` is CR-12, which the owner checks after pushing |

## CLI

| Finding | What it was | Verified by |
|---|---|---|
| F-PLAT-3 | CLI conventions: exit codes, stderr, version, nested roots | `TestNoArgsExit2Stderr`, `TestRuntimeErrorExit1Stderr` |

## Repo hygiene

| Finding | What it was | Verified by |
|---|---|---|
| F-PLAT-4 | Formatting and line endings | the gate runs a line-ending-insensitive gofmt check, and `.gitattributes` keeps LF in the index |
| F-PLAT-5 | No LICENSE file | no test: the MIT `LICENSE` file either exists or it does not |
| F-PLAT-7 | Dead code | no test: the dead code was deleted, and `go vet` runs on every change |

## Tests

| Finding | What it was | Verified by |
|---|---|---|
| F-PLAT-6 | Almost no tests | this document, and the suite it indexes |

## Documentation

| Finding | What it was | Verified by |
|---|---|---|
| F-DOC-1 | README and timeline docs claim behaviour the code does not have | this document, `TestDocumentedTestsExist`, and the "verified by" names the README carries beside each claim |
| F-DOC-2 | Shipped examples are broken | `TestExamples`; every shipped example runs through the command line and meets an assertion written for it |
| F-DOC-3 | ${UUID} and ${IP} are not what their names suggest | `TestIPStaysInCIDR` |

## Found while re-verifying the brief

Nine things the re-verification turned up that the brief itself did not
name.

| Finding | What it was | Verified by |
|---|---|---|
| N-1 | content_file, email bodies and attachments read from outside the YAML directory | `TestContentFileConfined`, `TestSourcesConfined`; and --allow-external-sources is recorded in the run manifest |
| N-2 | an invalid mode was swallowed for a directory create and for rotate | `TestValueRules`; every mode is parsed during validation, before anything is written |
| N-3 | parseDuration rejected "0d" | `TestDurations` |
| N-4 | the README linked to a ctf/ directory that does not exist | no test: the link is gone |
| N-5 | a failure left a partial tree with nothing saying so | `TestFailedRunMarksSidecarFailed` |
| N-6 | os.Root refuses stream paths and accepts names Windows then rewrites | `TestPathRules`; a spike, not a defect: it is why ads and motw open streams relative to a handle, and why the path policy rejects a trailing dot or space |
| N-7 | copy dropped streams, rotate stamped both files with the rotate time, rename replaced silently | `TestCopySemantics`, `TestCopyCarriesStreams`, `TestRotateKeepsRotatedTimes` |
| N-8 | an email with no date got no Date header and an mbox line dated 1970 | `TestEmailTimesFromDate`; a message with no date of its own is dated at its scheduled time |
| N-9 | go.mod had no toolchain line, although deflate, JPEG and SQLite bytes depend on one | `TestSidecarRecords`; go.mod pins the toolchain and the run manifest records the Go and generator versions |

## What the consumer asked for

The twelve requirements `plan.json` records. Each is checked against
`testdata/acceptance/quilldrop-lite.playbook.yaml` by its own subtest of
`TestConsumerAcceptance`, named for the requirement, and again by a
narrower test of the mechanism behind it.

| Requirement | Need | Verified by |
|---|---|---|
| CR-1 | A Sleuth Kit bodyfile from --timeline with a .body or .bodyfile name, or an explicit --timeline-format bodyfile. | `TestConsumerAcceptance`, `TestTimelineFormats` |
| CR-2 | The phishing email exactly as written in the playbook, CRLF line endings, parseable by net/mail. | `TestConsumerAcceptance`, `TestMailTemplateIsRFC5322` |
| CR-3 | The dropper (Invoice_MRD-88412.pdf.exe) and implant (svchost.exe) as valid PEs whose TimeDateStamp the playbook sets (0 for the 'scrubbed build time' lesson), sized to the requested length. | `TestConsumerAcceptance`, `TestPEHeaderFieldsEqualInputs`; two deviations: the acceptance scenario calls the implant quilld.exe with its own vendor in the version resource and zero filler, because Defender refused the write under the name svchost.exe even with zero filler and under a neutral name with the default filler and a Microsoft version resource; and `content_len` is the size of the overlay rather than of the whole file |
| CR-4 | Mark-of-the-Web on the dropper with templated HostUrl/ReferrerUrl, written without disturbing the file's times. | `TestConsumerAcceptance`, `TestAdsAndMotwKeepTimes` |
| CR-5 | The implant's 'quill' stream visible in the timeline. | `TestConsumerAcceptance`, `TestStreamsQuillAndSpaceNameWithSizes` |
| CR-6 | Creation times equal to scenario time, so that after the 12 March stomp exactly four files show mtime < crtime. | `TestConsumerAcceptance`, `TestQuilldropLiteStompCount` |
| CR-7 | bkp_20260311.zip as a real zip whose members are the staged documents, CRC-32 and size matching the originals. | `TestConsumerAcceptance`, `TestArchiveMembersMatchSources` |
| CR-8 | The 24 staging files actually deleted, and their deletion recorded in the ground truth. | `TestConsumerAcceptance`, `TestRefsDeleteAllStagingOnDisk` |
| CR-9 | A real gap in the beacon log's sequence numbers after the anti-forensics step. | `TestConsumerAcceptance`, `TestEditDeleteLines40to60` |
| CR-10 | An artefact every student can compare byte for byte: a deterministic content SHA256SUMS and/or modelled bodyfile, identical on every machine that runs the same fsagen version and seed. | `TestConsumerAcceptance`, `TestDeterminismHarness` |
| CR-11 | On Linux/macOS: either a clear refusal before anything is written, or a completed corpus with the NTFS-only artefacts listed as skipped. | `TestConsumerAcceptance`, `TestUnsupportedOpsFailBeforeAnyWrite` |
| CR-12 | go install github.com/aoiflux/fsagen@latest works. | no test: the owner runs `go install github.com/aoiflux/fsagen@latest` from a clean GOPATH after pushing |

