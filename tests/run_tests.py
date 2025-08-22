import json, subprocess, sys, os, pathlib
ROOT = pathlib.Path(__file__).resolve().parents[1]
CASES = json.loads(open(ROOT/"tests/cases.json","r",encoding="utf-8").read())
report=[]
for case in CASES:
    out = subprocess.run(
        [sys.executable, str(ROOT/"brute_decipher.py"), "-c", str(ROOT/"config.json"), case["cipher"]],
        text=True, capture_output=True, cwd=ROOT
    )
    report.append({"name": case["name"], "stdout": out.stdout, "stderr": out.stderr, "rc": out.returncode})
open(ROOT/"tests/report.json","w",encoding="utf-8").write(json.dumps(report, indent=2))
print("Wrote tests/report.json")
