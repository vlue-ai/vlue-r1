#!/usr/bin/env python3
"""golden_compare.py — ★술어 2: FL2.3 골든 9 정산-배분 멀티셋 == FL2.2 벡터(법 승계의 기계-증명).
실행: python3 frontier_vectors.py && python3 golden_compare.py  → GOLDEN_MULTISET_IDENTICAL true/false"""
import json, os, sys
_HERE = os.path.dirname(os.path.abspath(__file__))
a = json.load(open(os.path.join(_HERE, "..", "lang22", "results", "frontier_vectors.json")))["vectors"]
b = json.load(open(os.path.join(_HERE, "results", "frontier_vectors.json")))["vectors"]
def ms(v): return sorted(json.dumps(x, sort_keys=True) for x in v["expect"])
ok = set(a) == set(b)
for k in sorted(a):
    same = k in b and ms(a[k]) == ms(b[k]) and a[k]["expect_returned"] == b[k]["expect_returned"]
    ok &= same
    print(f"{k}: {'멀티셋 동일' if same else '★불일치'}" + ("" if same else f"  FL2.2={a[k]['expect']}  FL2.3={b.get(k, {}).get('expect')}"))
print(json.dumps({"GOLDEN_MULTISET_IDENTICAL": ok, "vectors": len(a)}))
sys.exit(0 if ok else 1)
