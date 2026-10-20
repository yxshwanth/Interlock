# Wave 0 baseline (recorded before any Wave 1 code change)

Tree: `5d9e946` on branch `wave-0-1`. Go 1.26.4, linux/amd64, i7-11800H (16 threads), 16 GB RAM. Every later parity claim is measured against these numbers.

## Corpora (`make fp-corpus`, `make cve-corpus`)

Both regenerated `docs/fp_corpus.md` and `docs/cve_corpus.md` with no diff, so they match the published numbers.

- fp-corpus: 75 scenarios (38 malicious, 37 benign)
  - detection rate (EXFIL-tier, non-gap malicious): 100.0% (31/31)
  - false-positive rate (any trip, benign): 18.9% (7/37)
  - false-positive rate (EXFIL-tier, benign): 0.0% (0/37)
  - known-gap misses: 7; bonus catches: 0
  - §12 entropy dark would-fire, benign: 0/37
- cve-corpus: 16 reconstructed scenarios, 7 architecturally out of scope
  - caught EXFIL: 12/15 (raw fraction over genuine CVE reconstructions, not a rate)
  - missed (documented gap): 4; missed (regression): 0; bonus catches: 0

## Engine benchmarks (`make bench`, `-benchtime=50ms`, single run)

Single short runs on a laptop: use for order of magnitude, not a regression gate. Re-run several times before setting budgets.

```
BenchmarkCanonicalEncodings-16                           	      91	    639643 ns/op	 7061857 B/op	     110 allocs/op
BenchmarkCheckOverlap_1Tainted-16                        	   14857	      4005 ns/op	    2912 B/op	      56 allocs/op
BenchmarkCheckOverlap_10Tainted-16                       	   10000	      5214 ns/op	    2912 B/op	      56 allocs/op
BenchmarkCheckOverlap_50Tainted-16                       	    5456	     10272 ns/op	    2912 B/op	      56 allocs/op
BenchmarkCheckOverlap_Scale/100-16                       	    3897	     14594 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_Scale/1000-16                      	     514	    111219 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_Scale/10000-16                     	      48	   1222600 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_MissPath/100-16                    	    3691	     14825 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_MissPath/1000-16                   	     506	    113764 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_MissPath/10000-16                  	      46	   1228540 ns/op	    2800 B/op	      56 allocs/op
BenchmarkCheckOverlap_DecodeMissPath/depth3-16           	     166	    354799 ns/op	    3568 B/op	      59 allocs/op
BenchmarkCheckOverlap_DecodeMissPath/depth4-16           	     171	    351832 ns/op	    3568 B/op	      59 allocs/op
BenchmarkCheckOverlap_DecodeMissPath/depth5-16           	     171	    351947 ns/op	    3568 B/op	      59 allocs/op
BenchmarkCheckOverlap_DecodeHitPath-16                   	   12213	      4863 ns/op	    2624 B/op	      36 allocs/op
BenchmarkCheckOverlap_HitPath/100-16                     	  825028	        72.42 ns/op	     144 B/op	       2 allocs/op
BenchmarkCheckOverlap_HitPath/1000-16                    	  745580	        79.57 ns/op	     144 B/op	       2 allocs/op
BenchmarkCheckOverlap_HitPath/10000-16                   	  942565	        67.10 ns/op	     144 B/op	       2 allocs/op
BenchmarkEvaluateRequest_Exfil_Scale/100-16              	    2208	    191383 ns/op	  156695 B/op	    2250 allocs/op
BenchmarkEvaluateRequest_Exfil_Scale/1000-16             	     397	    165948 ns/op	   30665 B/op	     439 allocs/op
BenchmarkEngine_IngestResult_TaintExtract-16             	      42	   2266394 ns/op	22351963 B/op	     464 allocs/op
BenchmarkCanonicalEncodings_PEMSized-16                  	      82	    791664 ns/op	 7518476 B/op	     133 allocs/op
BenchmarkEngine_IngestResult_TaintExtract_PEMSized-16    	      26	   4600067 ns/op	13211376 B/op	     374 allocs/op
BenchmarkEngine_EvaluateRequest_Exfil-16                 	    5642	    434798 ns/op	  390853 B/op	    5684 allocs/op
```

## HTTP engine delta (`make bench-http`, `-benchtime=500ms`, two runs)

```
BenchmarkHTTP_EngineDelta_ReadTicket/EngineOn              4.08 to 4.65 ms/op   (first run 4.51 ms)
BenchmarkHTTP_EngineDelta_ReadTicket/Passthrough           0.35 ms/op
BenchmarkHTTP_EngineDelta_MonitorSinkBenign/EngineOn       0.33 to 0.36 ms/op
BenchmarkHTTP_EngineDelta_MonitorSinkBenign/Passthrough    0.35 ms/op
```

This does not reproduce the ~536 µs read delta in `docs/performance.md`; the read path costs about 3.7 to 4.3 ms more with the engine on. The cause is not established here.

## Re-run after Wave 1 (entropy gate, privilege drop, taint caps, fd-keyed correlation)

`make fp-corpus cve-corpus` on the Wave 1 tree produced no diff in `docs/fp_corpus.md` or `docs/cve_corpus.md`. fp-corpus detection stays 100.0% (31/31), EXFIL-tier false positives stay 0/37, any-trip false positives stay 7/37; cve-corpus stays 12/15 with 0 regressions. The entropy gate (`minChunkEntropyBitsPerByte = 3.0`) therefore costs no detection on this corpus. Corpus scenarios feed synthetic events, so this says nothing about the kernel decode path.

## Kernel run on the deploy/ec2 VM

Ubuntu 24.04 AWS image, Linux 7.0.0-1014-aws, `m7i-flex.large`, BPF LSM active (booted once with `bpf` added), Go 1.26.4, run as root with `CGO_ENABLED=0`. `REQUIRE_KERNEL=1 scripts/verify-all.sh`: gofmt, build, vet, servers, test, test-layers, spdx, gate and kernel PASS; kernel suite 40 tests, 0 skipped.

The first run on this kernel failed and found real defects, all fixed in `7def404`:

- The verifier rejected the `sendmmsg`/iovec program (`R2 min value is negative`), so no BPF program loaded at all.
- `sendto` with a NULL address was still dropped, so review #1 was not actually fixed.
- `DropPostAttach` cleared `CAP_SYS_ADMIN` on one thread only.
- Two tests were wrong as written: the connect-flood test counted the Go runtime's eventfd writes as critical drops, and the `ReadContainerFile` oracle test assumed pid 1 has a different root than the test.

Not run: kernel 6.1 (the plan asks for it; only the current-LTS image was run), and the container-built `.o` (`make bpf-generate` needs Docker; the committed object was built with the VM's clang).

## Benchmarks on the VM

Five engine runs and three HTTP runs on the same VM. Worst runs were below the laptop-derived ceilings except the HTTP read path (9.32 ms against a 9.30 ms ceiling), so `docs/budgets.json` ceilings are now the larger of 2x the worst laptop run and 2x the worst VM run. CI-runner numbers are still not measured.

## Not yet recorded

- Kernel 6.1 run
- Benchmarks on a GitHub-hosted runner

## Flakes seen while recording

- One `go build` died with an internal compiler error (`collision: types v1beta3.FlowSchemaConditionType`) and one `-race` run crashed in the Go GC; both passed on immediate rerun. Probably memory pressure from other processes. Relevant to the §80 flake policy.
