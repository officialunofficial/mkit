# Nanocodex / Groq compatibility probes

Experimental localhost probes, not a production adapter. Nanocodex remains
unmodified. Verified with the npm release `nanocodex@0.5.0` and `ws@8.18.3` on
2026-09-09. The published package differs from current upstream source, which
has additional host and Cloudflare exports.

Run from a temporary directory to avoid adding dependencies or generated
workspace files to the repository:

```sh
probe_dir=$(mktemp -d /tmp/mkit-groq-probe.XXXXXX)
cp docs/reviews/probes/nanocodex-groq/*.mjs "$probe_dir/"
cd "$probe_dir"
npm install --ignore-scripts --no-audit --no-fund --save-exact nanocodex@0.5.0 ws@8.18.3
node local.mjs
# Supply the Groq key through stdin from an environment variable, not a literal.
printf '%s\n' "$GROQ_API_KEY" | node live.mjs
```

The local probe uses a scripted WebSocket endpoint without model inference.
It checks application tool execution and follow-up conversation handling, and
records the nonsensitive fixture request frames in `frames.json`.

The live probe keeps its key in memory and sends only synthetic task data to
Groq. It writes a model-generated `workspace/sum.mjs` and executes it with Node
to check two assertions. This is ordinary local code execution, not sandboxed
execution; use an isolated development environment. The shell/test tool has a
three-second timeout. The probe has an eight-request cap and a one-minute
deadline. It does not deploy anything.

## Observed result

- Unchanged nanocodex 0.5.0 connected to a localhost WebSocket adapter.
- Adapter mapped the internal model alias to Groq `openai/gpt-oss-120b`.
- Agent wrote `sum.mjs`, ran its tests, and reported success.
- A separate follow-up correctly recalled the filename.
- Four Groq requests consumed 493, 436, 441, and 525 reported total tokens
  respectively (1,895 total); one write and one test invocation occurred.

## Adapter behavior and limits

The live probe extracts `additional_tools` into Groq's top-level `tools`, handles
`generate:false` warmup locally, reconstructs full history for continuation,
and submits HTTP Responses requests. It returns completed responses over the
WebSocket. It buffers each response; token streaming was not tested.

It is deliberately limited to this text/direct-function-tool experiment.
Continuation state lives in memory, cancellation is not propagated upstream,
error handling closes the socket, and the protocol is not exhaustively
validated. No Cloudflare deployment, durable recovery, compaction, quota
enforcement, concurrent users, arbitrary project builds, or security isolation
was proven. The internal OpenAI model label/cost estimate must not be presented
as Groq metadata in a product. Production work must also enforce context limits
for the actual model.

Sources: [Nanocodex](https://github.com/gakonst/nanocodex),
[Groq Responses](https://console.groq.com/docs/responses-api),
[Groq rate limits](https://console.groq.com/docs/rate-limits).
