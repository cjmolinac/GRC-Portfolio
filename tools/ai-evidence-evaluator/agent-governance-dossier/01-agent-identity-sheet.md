# 01 · Agent Identity Sheet — GRC AI Evidence Evaluator

Format adapted from the agent-identity concept in the CertiProf AI Agent Manager (AIAM) study guide. Field names and numbering are my own structure, not a verbatim template.

Sheet version 1.0 · Last review 2026-11-19 · Next review 2027-02-19

| # | Field | Value |
|---|---|---|
| 1 | Agent ID | `AGT-001` — GRC AI Evidence Evaluator |
| 2 | Version | App v1.1 · Prompt v1.1 (versioned separately: a prompt change alters behaviour with identical code) |
| 3 | Business purpose | Give a GRC practitioner a first-pass, structured assessment of a piece of control or AI-governance evidence, and generate auditor-style challenge questions. It informs; it does not trigger work |
| 4 | Owner (accountable human) | Carlos J. Molina |
| 5 | Autonomy level | **Level 2 — Automation.** One defined task (evaluate a submitted text); no tool chaining; no action on external systems; a human reads every output before anything happens. It becomes Level 3 the day it is connected to a ticketing system, evidence repository or workflow |
| 6 | Model access | Groq API, user-supplied key. Underlying model identifiers, tried in this order: `openai/gpt-oss-120b`, `openai/gpt-oss-20b`, `llama-3.3-70b-versatile` (listed in `GROQ_MODEL_CANDIDATES`; the provider may retire any of them). Temperature 0. The model that actually answered is recorded in each report, and a warning shows when it is not the first choice |
| 7 | Data it may read | Text the user pastes. **Not permitted:** client-confidential, personal or regulated data (visible warning in the UI) |
| 8 | Data it may write | Nothing persistent. Browser-session history only; exports are user-initiated |
| 9 | Permissions (least privilege) | Network: `api.groq.com` only (Content-Security-Policy `connect-src`). No storage, images, frames or form posts |
| 10 | Third parties | Groq (model hosting). Evidence leaves the browser to Groq |
| 11 | Prohibited uses | Final audit opinion; legal advice; classifying a system's EU AI Act risk tier; use on confidential client evidence |
| 12 | Human oversight | Every output is labelled "AI-generated draft — requires review by a qualified professional". Verdict is derived from the score in code; contradictions are surfaced. The human reads the output **before** it has any effect |
| 13 | Escalation | Model unavailable, unparseable output or verdict/score contradiction → shown on screen; the user decides. Fallback to another model is disclosed in the report. No automatic escalation exists: the human is the escalation path. Output has no downstream recipient |
| 14 | Suspension criteria | Output rendered as active content; evidence of data leaving to any host other than Groq; score range across repeated runs of the same case above a threshold to be set by the reproducibility test (piece 6; not yet run) |
| 15 | Review | Quarterly, and on any change listed below |

## Change triggers — what forces a re-review of this sheet

| If this changes | Fields to revisit | Why |
|---|---|---|
| The tool writes to an external system | 2, 3, 5, 8, 9, 10, 11, 12, 13, 14, 15 | The effect can happen *before* a human reads the output; oversight becomes after-the-fact |
| Model list or provider changes | 2, 6, 10 | Behaviour can drift with no change to the code |
| Prompt text changes | 2, then rerun the reproducibility test | Same code, different behaviour |
| Accepted input widens (e.g. client evidence allowed) | 7, 10, 11, 14 | Data classification and third-party exposure change |
| A second person operates the tool | 12, 13 | Oversight depends on the operator following a procedure |

The owner of a queue that receives the agent's output is not the owner of the agent (field 4); that responsibility belongs in field 13.
