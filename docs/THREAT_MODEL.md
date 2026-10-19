# Threat model

This document is the deliverable, not the disclaimer. A safety-evaluation harness whose
own residual risk is unstated cannot be used to make claims about anything else.

---

## 1. What is being protected

The asset is **the validity of an evaluation**, not the model and not the parties.

Three things must hold for a finding to mean anything:

| Property | Violated when |
|---|---|
| **Payload confidentiality** | Blue learns Red's corpus before the test concludes, and pre-tunes to it. The test then measures the rule, not the model. |
| **Defence confidentiality** | Red infers Blue's rules from feedback and steers around them. The test measures evasion skill, not coverage. |
| **Session independence** | State from one session influences another. A finding reproduces only in the contaminated environment and ships to the client as real. |

The failure mode that matters is not a breach. It is a **report nobody downstream can
falsify** — where a false positive and a false negative are indistinguishable after
the fact.

---

## 2. Parties and what each is assumed to do

| Party | Trusted to | Assumed to attempt |
|---|---|---|
| **Red** | Nothing beyond protocol conformance | Reach the model directly; extract session context; infer Blue's rules from latency or response shape; replay traffic |
| **Blue** | Nothing beyond protocol conformance | Obtain Red's payloads early; infer the attack corpus from advisory timing or volume |
| **Model server** | Answer what the gateway asks | Leak its context when prompted; leak across sessions if its store is shared |
| **Gateway** | **Everything** | — (see §5) |
| **Operator** | Deploy correctly | Misconfigure under resource pressure (§6) |

Red and Blue are mutually distrusting and both distrust the harness. The gateway is the
single trusted component, which is this design's central weakness and is treated as
such below.

---

## 3. Trust boundaries

```
  ┌────────┐                ┌───────────┐                ┌────────────┐
  │  RED   │══ red_edge ═══▶│           │══ link ═══════▶│ red-model  │
  └────────┘                │  GATEWAY  │                └────────────┘
  ┌────────┐                │           │                ┌────────────┐
  │  BLUE  │══ blue_edge ══▶│           │══ link ═══════▶│ blue-model │
  └────────┘                └───────────┘                └────────────┘
                                  │
                            hash-chained audit log
```

Every `══` is a boundary. The gateway is the only component attached to more than one
network; in container mode, removing it leaves no path from any party to any model.

---

## 4. Protected — with the mechanism and the evidence

| Claim | Mechanism | Evidence |
|---|---|---|
| No Red→Blue or Red→model path | Separate internal networks; gateway is the only multi-homed container. In process mode, the model additionally rejects any caller without the gateway key. | Demo act 1; `party.probe` distinguishes `no_route` from `rejected` |
| Blue never receives the payload | Advisory restricted to four fields **drawn from a closed vocabulary**, asserted at the gateway before release | Demo act 2; `TestAdvisory` |
| Cross-session leakage is detected **and attributed** | Party-keyed DNA markers on every mediated message; a foreign marker quarantines the response and names its source session | Demo act 3b; `TestDna` |
| No shared context store | One model server and one session per party | `docker-compose.yml` topology; act 3a shows the clean case does not false-positive |
| Observable timing channel is reduced | Fixed-tick release | Measured curve in README; `artifacts/timing.json` |
| Log edits are evident and localised | SHA-256 chain plus per-entry content digest; keyed checkpoints | Demo act 5; `TestAudit` |
| A finding reports a rate, not a boolean | Shadow Replay across independently opened sessions, Wilson interval | Demo act 4 |

A design note worth stating: Blue's advisory is **constructed from a closed vocabulary**
rather than scanned for leaked payload. We built the scanning version first and it
false-positived on the shared English substring `" instruction"`. An allowlist makes
payload leakage impossible by construction; the substring scan is retained only as a
backstop against a future field that is not vocabulary-constrained.

---

## 5. Not protected — stated up front

**Shared kernel.** Containers, not VMs. A container escape defeats every property in
this document simultaneously. Upgrading the boundary to gVisor, Kata Containers or a
dedicated microVM is a configuration change to `deploy/`, not a redesign — but it has
not been done or measured here.

**The gateway is one trusted component.** It routes, redacts, logs and pads. Compromise
it and every property falls together. It is not formally verified, and its code is the
largest single thing a reviewer must read and believe. Splitting the redaction and
logging duties into separate processes with separate keys would reduce this; it is not
done.

**Microarchitectural and physical channels.** Cache, branch predictor, power, EM. CPU
pinning raises the cost of exploiting them; it does not close them. Out of scope and
unmeasured.

**Resource and availability channels.** CPU and memory contention between parties is a
channel. `mem_limit`, `cpus` and `pids_limit` are set in compose, but we have not
measured what remains.

**Content-only detection.** DNA sees markers. Paraphrase, summarisation and semantic
influence carry none. A green detector is not a proof of non-contamination, and
`TestDna.test_paraphrase_is_not_detected` asserts this blind spot so the claim in the
README cannot quietly drift away from the code.

**The model is a mock.** A deterministic rule engine with one seeded stochastic branch.
This is a deliberate scope choice: our claims are about the channel between parties, and
a mock lets us *force* the exact leak we want to detect, which a real model would not.
The cost is that nothing here is evidence about real model behaviour.

**Symmetric checkpoints.** HMAC, not a signature. A verifier must hold the audit key,
which means a verifier can also forge. Public-key signing is the upgrade; the entry
format leaves room for it.

**Log truncation.** Dropping entries from the tail leaves a shorter but internally
consistent chain. Only a checkpoint covering a later index exposes it, which requires a
verifier holding an externally recorded head.
`TestAudit.test_truncation_is_not_detected_without_a_checkpoint` asserts this.

**Secret distribution.** `DOUBLEBLIND_SECRET` is a single shared secret from which all
keys are derived. Real deployments need per-party keys distributed out of band and
rotated. Not implemented.

---

## 6. Where it fails first — ranked by likelihood, not severity

**1. Misconfiguration re-introducing sharing.**
Someone points two parties at one model endpoint to save memory, or enables a shared
cache for throughput. Most likely failure in production, and the one DNA catches
reliably. Reproduced on demand by `scripts/demo.py --only 3`.

**2. A leak that carries no marker.**
Semantic influence rather than copied text: the model's behaviour in session B is shaped
by session A without any marked token crossing. The detector stays green and the test is
already contaminated. We consider this the most dangerous residual risk, because it is
silent and the system's own reporting will say everything is fine.

**3. A gateway bug, not a gateway compromise.**
An unpadded error path, a missed redaction field, a log write skipped on an exception.
Mitigated partly by routing all releases through one function and asserting the advisory
shape rather than trusting it — and the advisory check caught a real case-folding bug in
our own code during development.

**4. Clock and scheduler jitter defeating the tick.**
Fixed-tick release assumes the scheduler can hit a boundary. Under host load the
distribution widens and the advantage rises. The measurement script must be re-run on
the deployment hardware; numbers from a laptop do not transfer.

---

## 7. Residual risk statement

DOUBLEBLIND reduces cross-tenant leakage between adversarial evaluation parties and
produces verifiable evidence about the conditions of a run. It does **not** provide
isolation guarantees equivalent to separate physical hosts or hardware-enforced
enclaves, and it does not detect contamination that carries no marker.

A Proof Pack asserts that the recorded conditions held. It does not assert that the
finding is real, that the model is safe, or that no uninstrumented channel was used.
Any downstream use — including conformity assessment — must treat the pack as evidence
about process integrity, not as a safety certificate.
