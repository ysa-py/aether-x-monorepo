# ML environment verification — 2026-07-27

**Scope:** environment only. No trained model, traffic dataset, classifier
metric, or promoted ONNX artifact was produced in this run.

## Reproducible command

```bash
python3 -m venv /tmp/aether-ml-venv
/tmp/aether-ml-venv/bin/python -m pip install --disable-pip-version-check \
  --no-cache-dir -r ai-training/requirements-ml-environment.txt
/tmp/aether-ml-venv/bin/python /tmp/aether-onnx-environment-smoke.py
```

The smoke script creates a temporary 166-byte ONNX `Add` graph, runs
`onnx.checker`, loads it with the real `onnxruntime` CPU execution provider,
executes one forward pass, asserts the output, and deletes the temporary file.
It is solely an environment test graph, not an Aether-X model or a training
artifact.

## Actual output

```text
python=3.11.2
numpy=2.3.5
onnx=1.19.1
onnxruntime=1.28.0
scikit-learn=1.8.0
onnx_smoke_artifact_bytes=166
onnx_smoke_provider=CPUExecutionProvider
onnx_smoke_result=[[3.25, 1.0]]
onnx_smoke_load_and_forward_ms=3.163
onnx_environment_round_trip=PASS
```

## Result

The offline Python training/inference environment is available in the agent
sandbox. It remains isolated from production Rust/Go images.

## Explicit blocker

**Awaiting real labeled dataset — human decision pending, not an engineering
task.** The repository has no authorized, manifest-backed real traffic campaign
with independent ground truth. Therefore no model is trained, no model accuracy
or resource metric is reported, and no ONNX artifact is added to production.
