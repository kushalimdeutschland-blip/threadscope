# Custom sandbox adapter

Dynamic analysis always runs in [`scripts/sandbox_worker.py`](../../scripts/sandbox_worker.py), never inside the FastAPI web process. To plug in your own automation (custom VM script, internal API, etc.), use the **script** backend.

## Configuration

```bash
# .env
SANDBOX_BACKEND=script
SANDBOX_SCRIPT=/opt/threatscope/scripts/my_analyzer.py
# Optional interpreter override
SANDBOX_SCRIPT_PYTHON=python3
```

Start the worker:

```bash
python scripts/sandbox_worker.py
```

Upload a file with **Run dynamic analysis** checked (`.exe` or `.apk` only).

## Script contract

Your script receives:

```text
python my_analyzer.py --sample /path/to/sample --kind apk --filename evil.apk
```

Print **one JSON object** to stdout:

```json
{
  "status": "completed",
  "risk_score": 75,
  "behaviors": ["Contacted 203.0.113.1:443"],
  "network_iocs": ["203.0.113.1"],
  "signatures": ["Suspicious API"],
  "tags": ["Custom"],
  "summary": "Short behavior summary"
}
```

On failure:

```json
{"status": "failed", "error": "reason"}
```

ThreatScope maps this into [`DynamicReport`](../../services/sandbox/base.py) and merges it with static results.

## Reference implementation

See [`scripts/example_sandbox_analyzer.py`](../../scripts/example_sandbox_analyzer.py) — a minimal stub you can copy and extend.

## Adapter source

[`services/sandbox/script_adapter.py`](../../services/sandbox/script_adapter.py) implements [`SandboxAdapter`](../../services/sandbox/base.py). For tighter integration (REST API, queue, SSH to another host), copy this file and register a new backend in [`services/sandbox/registry.py`](../../services/sandbox/registry.py).

## Security

- Run the worker on an **isolated lab VM**.
- The script runs with the worker’s privileges — treat samples as malicious.
- Do not point `SANDBOX_SCRIPT` at web-writable paths.
