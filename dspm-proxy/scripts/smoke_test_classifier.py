import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from classifier.engine import DSPMClassifier

CASES = [
    ("AWS key", "Here is our AWS key: AKIAABCDEFGHIJKLMNOP for the deploy script.", "Sensitive/Proprietary"),
    ("GitHub token", "use this token ghp_" + "a" * 36 + " to clone the repo", "Sensitive/Proprietary"),
    ("Private key block", "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...", "Sensitive/Proprietary"),
    ("Credit card", "Please charge card 4111 1111 1111 1111 for the order.", "Sensitive/Proprietary"),
    ("SSN", "His SSN is 856-45-6789 for the background check.", "Sensitive/Proprietary"),
    ("Safe banana bread", "What is a good recipe for banana bread?", "Safe"),
    ("Safe weather", "Can you summarize this week's weather forecast for Boston?", "Safe"),
    ("Safe generic code question", "How do I write a for loop in Python?", "Safe"),
]

clf = DSPMClassifier()
failures = 0
for name, text, expected in CASES:
    result = clf.classify(text)
    ok = result.classification == expected
    if not ok:
        failures += 1
    print(f"[{'OK' if ok else 'FAIL'}] {name}: expected={expected} got={result.classification} "
          f"conf={result.confidence_score} trigger={result.trigger!r} entity={result.entity_type}")

print(f"\n{len(CASES) - failures}/{len(CASES)} passed")
sys.exit(1 if failures else 0)
