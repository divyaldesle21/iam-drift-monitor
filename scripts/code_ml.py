import os
import sys
import re
import json
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import cross_val_score

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from taint_analysis import (TAINT_SOURCES, DANGEROUS_SINKS, SANITIZERS,
                            DIRECT_PATTERNS, detect_language, is_noise, SKIP_DIRS)

FEATURE_NAMES = [
    "loc", "taint_sources", "dangerous_sinks", "sanitizer_calls",
    "string_concat_in_query", "sql_keywords", "exec_calls",
    "file_ops", "http_calls", "crypto_calls",
    "sink_to_sanitizer_ratio", "source_sink_density"
]

def extract_code_features(content, lang):
    lines = content.split("\n")
    loc = len([l for l in lines if l.strip() and not l.strip().startswith("//")])
    n_src = 0
    for pat in TAINT_SOURCES.get(lang, []):
        n_src += len([m for m in re.finditer(pat, content) if not is_noise(content, m.start())])
    n_sink = 0
    for d in DANGEROUS_SINKS.values():
        for pat in d["patterns"]:
            n_sink += len([m for m in re.finditer(pat, content) if not is_noise(content, m.start())])
    n_san = sum(len(re.findall(s, content)) for s in SANITIZERS)
    concat_query = len(re.findall(r"(?i)\"\s*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+", content))
    sql_kw = len(re.findall(r"(?i)\b(SELECT|INSERT INTO|UPDATE|DELETE FROM|WHERE)\b", content))
    exec_calls = len(re.findall(r"(exec|system|Popen|Runtime\.getRuntime)", content))
    file_ops = len(re.findall(r"(new\s+File|FileInputStream|open\s*\(|Paths\.get)", content))
    http_calls = len(re.findall(r"(new\s+URL|openConnection|requests\.|HttpClient)", content))
    crypto = len(re.findall(r"(?i)(MessageDigest|hashlib|Cipher\.getInstance)", content))
    ratio = n_sink / max(n_san, 1)
    density = (n_src + n_sink) / max(loc, 1) * 100
    return [loc, n_src, n_sink, n_san, concat_query, sql_kw, exec_calls,
            file_ops, http_calls, crypto, ratio, density]

def label_file(content, lang):
    """Ground truth: file is vulnerable if it has an unsanitized dangerous pattern"""
    for d in DIRECT_PATTERNS.values():
        for pat in d["patterns"]:
            for m in re.finditer(pat, content):
                if not is_noise(content, m.start()):
                    return 1
    concat = len(re.findall(r"(?i)\w+\s*=\s*\"\s*(SELECT|INSERT|UPDATE|DELETE)[^\"]*\"\s*\+", content))
    if concat > 0:
        return 1
    return 0

def build_corpus(repo_path):
    X, y, meta = [], [], []
    for root, dirs, files in os.walk(repo_path):
        dirs[:] = [d for d in dirs if d.lower() not in SKIP_DIRS]
        for fn in files:
            fp = os.path.join(root, fn)
            lang = detect_language(fp)
            if not lang:
                continue
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    content = fh.read()
            except Exception:
                continue
            if len(content.strip()) < 100:
                continue
            X.append(extract_code_features(content, lang))
            y.append(label_file(content, lang))
            meta.append(fp)
    return np.array(X), np.array(y), meta

def train_and_evaluate(X, y):
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    model = RandomForestClassifier(n_estimators=200, random_state=42,
                                   class_weight="balanced", max_depth=8)
    scores = {}
    if len(set(y)) > 1 and min(np.bincount(y)) >= 5:
        for metric in ["precision", "recall", "f1", "accuracy"]:
            cv = cross_val_score(model, Xs, y, cv=5, scoring=metric)
            scores[metric] = (cv.mean(), cv.std())
    model.fit(Xs, y)
    return model, scaler, scores

def print_ml_report(X, y, meta, model, scaler, scores, repo_path):
    print("\n" + "=" * 72)
    print("ML VULNERABILITY CLASSIFIER (Supervised Random Forest)")
    print("Trained on Source Code Features - Not Infrastructure")
    print("=" * 72)
    n_vuln = int(sum(y))
    print("\nFiles in corpus     : " + str(len(y)))
    print("Labeled vulnerable  : " + str(n_vuln))
    print("Labeled clean       : " + str(len(y) - n_vuln))
    print("Features per file   : " + str(len(FEATURE_NAMES)))
    print("\nCODE FEATURES USED (no IAM, no infrastructure):")
    print("-" * 72)
    for i, name in enumerate(FEATURE_NAMES):
        print("  " + str(i + 1).rjust(2) + ". " + name)
    if scores:
        print("\n5-FOLD CROSS-VALIDATED PERFORMANCE:")
        print("-" * 72)
        print("  Metric        Mean     Std")
        for k in ["precision", "recall", "f1", "accuracy"]:
            if k in scores:
                m, s = scores[k]
                print("  " + k.ljust(13) + ("%.3f" % m).ljust(9) + ("+/- %.3f" % s))
    imp = model.feature_importances_
    order = np.argsort(imp)[::-1]
    print("\nTOP PREDICTIVE CODE FEATURES:")
    print("-" * 72)
    for idx in order[:6]:
        bar = "#" * int(imp[idx] * 60)
        print("  " + FEATURE_NAMES[idx].ljust(26) + bar + " " + ("%.3f" % imp[idx]))
    Xs = scaler.transform(X)
    proba = model.predict_proba(Xs)[:, 1]
    ranked = np.argsort(proba)[::-1]
    print("\nHIGHEST RISK FILES (model confidence):")
    print("-" * 72)
    shown = 0
    for idx in ranked:
        if proba[idx] < 0.5:
            break
        rel = os.path.relpath(meta[idx], repo_path)
        score = int(proba[idx] * 100)
        bar = "X" * (score // 10) + "." * (10 - score // 10)
        label = "VULNERABLE" if y[idx] == 1 else "predicted"
        print("  [" + bar + "] " + str(score).rjust(3) + "%  " + label.ljust(11) + rel[-58:])
        shown += 1
        if shown >= 12:
            break
    print("\n" + "=" * 72)
    print("ML VERDICT: classifier trained on code structure, not IAM policy.")
    print("=" * 72 + "\n")

if __name__ == "__main__":
    repo = sys.argv[1] if len(sys.argv) > 1 else "/app/target"
    print("Building code feature corpus from: " + repo)
    X, y, meta = build_corpus(repo)
    if len(X) == 0:
        print("No source files found.")
        sys.exit(0)
    model, scaler, scores = train_and_evaluate(X, y)
    print_ml_report(X, y, meta, model, scaler, scores, repo)