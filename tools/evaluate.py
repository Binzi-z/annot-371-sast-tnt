"""按标注样本计算召回率与误报率（评测基线 / 改造后对比用）。

    python tools/evaluate.py --report out/report.json --labels samples/labels.json
"""

import argparse
import json
import os


def norm(p):
    return p.replace("\\", "/").lstrip("./")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--report", default="out/report.json")
    ap.add_argument("--labels", default="samples/labels.json")
    args = ap.parse_args()

    labels = json.load(open(args.labels, encoding="utf-8"))["labels"]
    findings = json.load(open(args.report, encoding="utf-8"))["findings"]

    hit = set()
    for f in findings:
        hit.add((norm(f["file"]), int(f["line"])))

    tp = fp = fn = tn = 0
    details = []
    for lab in labels:
        key = (norm(lab["file"]), int(lab["line"]))
        found = any(k[0].endswith(key[0]) and k[1] == key[1] for k in hit)
        if lab["vuln"] and found:
            tp += 1
        elif lab["vuln"] and not found:
            fn += 1
            details.append(("MISS", key, lab["sink"]))
        elif (not lab["vuln"]) and found:
            fp += 1
            details.append(("FALSE-POSITIVE", key, lab["sink"]))
        else:
            tn += 1

    def ratio(a, b):
        return round(100.0 * a / b, 1) if b else 0.0

    recall = ratio(tp, tp + fn)
    precision = ratio(tp, tp + fp)
    fpr = ratio(fp, fp + tn)

    print(f"labels={len(labels)} tp={tp} fp={fp} fn={fn} tn={tn}")
    print(f"recall={recall}%  precision={precision}%  false-positive-rate={fpr}%")
    for d in details[:15]:
        print("  ", d)

    if recall < 85 or fpr > 15:
        print("=> 未达标（目标：recall >= 85%，误报率 <= 15%）")
        raise SystemExit(1)
    print("=> 达标")


if __name__ == "__main__":
    main()
