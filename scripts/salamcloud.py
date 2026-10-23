#!/usr/bin/env python3
"""校验 control/、生成并签名 api/v1/control.json。

  python3 scripts/salamcloud.py validate          只校验
  python3 scripts/salamcloud.py build             校验 + 生成 + 签名（需环境变量 SALAMCLOUD_SIGNING_KEY）
  python3 scripts/salamcloud.py hash-order 订单号  计算订单号哈希（与 App、SalamCloud 相同算法）
"""
import base64, datetime as dt, hashlib, json, os, re, subprocess, sys, tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "api" / "v1" / "control.json"
SIG = ROOT / "api" / "v1" / "control.json.sig"
CST = dt.timezone(dt.timedelta(hours=8))


def read(name):
    with open(ROOT / "control" / name, encoding="utf-8") as f:
        return json.load(f)


def fail(msg):
    print(f"::error::{msg}")
    sys.exit(1)


def normalize_order(order: str) -> str:
    return re.sub(r"\s+", "", order).upper()


def hash_order(order: str, kdf: dict) -> str:
    return hashlib.pbkdf2_hmac("sha256", normalize_order(order).encode("utf-8"),
                               bytes.fromhex(kdf["salt"]), int(kdf["iterations"]), int(kdf["length"])).hex()


def parse_time(text, where):
    try:
        moment = dt.datetime.fromisoformat(text)
    except Exception:
        fail(f"{where}: 时间格式不对（要 ISO 8601，例如 2026-11-01T00:00:00+08:00）：{text}")
    if moment.tzinfo is None:
        fail(f"{where}: 时间必须带时区（例如 +08:00）：{text}")
    return moment


def validate():
    gate, orders, beta = read("gate.json"), read("orders.json"), read("beta.json")
    if not isinstance(gate.get("enabled"), bool):
        fail("gate.json: enabled 必须是 true/false")
    if not isinstance(gate.get("from_version_code"), int) or gate["from_version_code"] < 0:
        fail("gate.json: from_version_code 必须是非负整数")
    if not isinstance(gate.get("challenge"), int) or gate["challenge"] < 0:
        fail("gate.json: challenge 必须是非负整数（每发起一次验证 +1）")
    if "max_attempts" in gate and (not isinstance(gate.get("max_attempts"), int)
                                   or not 1 <= gate["max_attempts"] <= 20):
        fail("gate.json: max_attempts 必须是 1–20 的整数")
    for key, low, high in (("pending_round", 0, 10**9), ("grace_attempts", 0, 10)):
        if key in gate and (not isinstance(gate.get(key), int) or not low <= gate[key] <= high):
            fail(f"gate.json: {key} 必须是 {low}–{high} 的整数")
    if "enroll_new_devices" in gate and not isinstance(gate.get("enroll_new_devices"), bool):
        fail("gate.json: enroll_new_devices 必须是 true/false")
    reverify = gate.get("reverify", {})
    if not isinstance(reverify, dict) or any(
            not re.fullmatch(r"[0-9a-f]{64}", str(k)) or not isinstance(v, int) or v < 0
            for k, v in reverify.items()):
        fail("gate.json: reverify 只能是 {订单哈希: 非负整数}")
    for key in ("title", "message"):
        if not isinstance(gate.get(key), str) or not gate[key].strip() or len(gate[key]) > 200:
            fail(f"gate.json: {key} 需要 1–200 字")
    kdf = orders.get("kdf") or {}
    if not re.fullmatch(r"[0-9a-f]{32,}", str(kdf.get("salt", ""))) or int(kdf.get("iterations", 0)) < 10000:
        fail("orders.json: kdf.salt / kdf.iterations 不合法")
    for key in ("orders", "revoked"):
        values = orders.get(key)
        if not isinstance(values, list) or any(not re.fullmatch(r"[0-9a-f]{64}", str(v)) for v in values):
            fail(f"orders.json: {key} 只能放 64 位十六进制哈希（不要放明文订单号）")
        if len(set(values)) != len(values):
            fail(f"orders.json: {key} 有重复项")
    rules = beta.get("rules")
    if not isinstance(rules, list):
        fail("beta.json: rules 必须是数组")
    for i, rule in enumerate(rules):
        where = f"beta.json rules[{i}]"
        codes = rule.get("version_codes")
        if (not isinstance(codes, list) or len(codes) != 2 or not all(isinstance(c, int) for c in codes)
                or codes[0] > codes[1]):
            fail(f"{where}: version_codes 要写成 [最小, 最大]")
        if not isinstance(rule.get("enabled"), bool):
            fail(f"{where}: enabled 必须是 true/false")
        parse_time(str(rule.get("expires_at", "")), where)
        if not isinstance(rule.get("message"), str) or not rule["message"].strip():
            fail(f"{where}: message 不能为空")
    # features.json is optional: without it every feature switch is off.
    features = read("features.json") if (ROOT / "control" / "features.json").exists() else {}
    for k, v in features.items():
        if not k.startswith("$") and not isinstance(v, bool):
            fail(f"features.json: {k} 必须是 true/false")
    return gate, orders, beta, features


def build():
    gate, orders, beta, features = validate()
    key = os.environ.get("SALAMCLOUD_SIGNING_KEY", "").strip()
    if not key:
        fail("缺少 SALAMCLOUD_SIGNING_KEY（仓库 Actions Secret）")
    previous = 0
    if OUT.exists():
        try:
            previous = int(json.loads(OUT.read_text(encoding="utf-8")).get("serial", 0))
        except Exception:
            previous = 0
    strip = lambda d: {k: v for k, v in d.items() if not k.startswith("$")}
    control = {
        "format": 1,
        "serial": previous + 1,
        "issued_at": dt.datetime.now(CST).replace(microsecond=0).isoformat(),
        "order_gate": {**strip(gate), "kdf": orders["kdf"], "orders": orders["orders"], "revoked": orders["revoked"]},
        "beta": beta["rules"],
        "features": strip(features),
    }
    body = json.dumps(control, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode("utf-8")
    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_bytes(body)
    # ECDSA P-256 / SHA-256 over the exact bytes of control.json; DER signature, base64.
    with tempfile.NamedTemporaryFile("w", delete=False) as handle:
        handle.write(key + "\n")
        key_path = handle.name
    try:
        der = subprocess.run(["openssl", "dgst", "-sha256", "-sign", key_path, str(OUT)],
                             check=True, capture_output=True).stdout
    finally:
        os.unlink(key_path)
    SIG.write_text(base64.b64encode(der).decode("ascii") + "\n", encoding="ascii")
    public = ROOT / "keys" / "control-signing-public.pem"
    check = subprocess.run(["openssl", "dgst", "-sha256", "-verify", str(public), "-signature", "/dev/stdin", str(OUT)],
                           input=der, capture_output=True)
    if check.returncode != 0:
        fail("签名与 keys/control-signing-public.pem 不匹配：Secret 里的私钥不是这对公钥的")
    print(f"control.json serial {control['serial']} 已签名")


if __name__ == "__main__":
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command == "validate":
        validate()
        print("ok")
    elif command == "build":
        build()
    elif command == "hash-order" and len(sys.argv) > 2:
        print(hash_order(sys.argv[2], read("orders.json")["kdf"]))
    else:
        print(__doc__)
        sys.exit(2)
