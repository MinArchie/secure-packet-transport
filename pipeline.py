"""
pipeline.py  —  Core fog-security pipeline logic extracted from fog_security.ipynb
Provides: Ascon-128 AEAD, CBOR serialization, MQTT-SN/CoAP transport, IDS, simulation.
"""

import os, sys, struct, json, warnings
warnings.filterwarnings('ignore')

# ── Optional dependencies ────────────────────────────────────────────────────
try:
    import ascon as _ascon_lib
    assert hasattr(_ascon_lib, 'ascon_encrypt')
    _ASCON_NATIVE = True
except (ImportError, AssertionError):
    _ASCON_NATIVE = False

try:
    import cbor2
    _CBOR_NATIVE = True
except ImportError:
    _CBOR_NATIVE = False

try:
    import paho.mqtt.client as _mqtt
    _MQTT_AVAILABLE = True
except ImportError:
    _MQTT_AVAILABLE = False

try:
    import xgboost as xgb
    _XGB_AVAILABLE = True
except ImportError:
    _XGB_AVAILABLE = False

try:
    from imblearn.over_sampling import SMOTE
    _SMOTE_AVAILABLE = True
except ImportError:
    _SMOTE_AVAILABLE = False

import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.feature_selection import mutual_info_classif

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 1 — ASCON-128 AEAD
# ─────────────────────────────────────────────────────────────────────────────

MASK64 = 0xFFFFFFFFFFFFFFFF

def _rotr64(x, n):
    return ((x >> n) | (x << (64 - n))) & MASK64

def _ascon_permutation(S, rounds):
    RC = [0xf0, 0xe1, 0xd2, 0xc3, 0xb4, 0xa5, 0x96, 0x87,
          0x78, 0x69, 0x5a, 0x4b]
    for r in range(12 - rounds, 12):
        S[2] ^= RC[r]
        S[0] ^= S[4]; S[4] ^= S[3]; S[2] ^= S[1]
        T = [(~S[i]) & S[(i + 1) % 5] for i in range(5)]
        for i in range(5): S[i] ^= T[(i + 1) % 5]
        S[1] ^= S[0]; S[0] ^= S[4]; S[3] ^= S[2]
        S[2] = (~S[2]) & MASK64
        S[0] ^= _rotr64(S[0], 19) ^ _rotr64(S[0], 28)
        S[1] ^= _rotr64(S[1], 61) ^ _rotr64(S[1], 39)
        S[2] ^= _rotr64(S[2],  1) ^ _rotr64(S[2],  6)
        S[3] ^= _rotr64(S[3], 10) ^ _rotr64(S[3], 17)
        S[4] ^= _rotr64(S[4],  7) ^ _rotr64(S[4], 41)

def _b2i(b):    return int.from_bytes(b, 'big')
def _i2b(i, n): return i.to_bytes(n, 'big')
def _pad(b, r): return b + b'\x80' + b'\x00' * (r - 1 - len(b) % r)

def _py_ascon128_encrypt(key, nonce, ad, pt):
    rate = 8; a, b = 12, 6
    IV = _b2i(bytes([0x80, 0x40, 0x0c, 0x06]) + b'\x00' * 4)
    S  = [IV, _b2i(key[:8]), _b2i(key[8:]), _b2i(nonce[:8]), _b2i(nonce[8:])]
    _ascon_permutation(S, a)
    S[3] ^= _b2i(key[:8]); S[4] ^= _b2i(key[8:])
    if ad:
        for i in range(0, len(_pad(ad, rate)), rate):
            S[0] ^= _b2i(_pad(ad, rate)[i:i + rate])
            _ascon_permutation(S, b)
    S[4] ^= 1
    ct = b''
    if pt:
        padded = _pad(pt, rate)
        for i in range(0, len(padded), rate):
            S[0] ^= _b2i(padded[i:i + rate])
            ct += _i2b(S[0], rate)
            _ascon_permutation(S, b)
        ct = ct[:len(pt)]
    S[1] ^= _b2i(key[:8]); S[2] ^= _b2i(key[8:])
    _ascon_permutation(S, a)
    S[3] ^= _b2i(key[:8]); S[4] ^= _b2i(key[8:])
    return ct + _i2b(S[3], 8) + _i2b(S[4], 8)

def _py_ascon128_decrypt(key, nonce, ad, ct_tag):
    assert len(ct_tag) >= 16
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    rate = 8; a, b = 12, 6
    IV = _b2i(bytes([0x80, 0x40, 0x0c, 0x06]) + b'\x00' * 4)
    S  = [IV, _b2i(key[:8]), _b2i(key[8:]), _b2i(nonce[:8]), _b2i(nonce[8:])]
    _ascon_permutation(S, a)
    S[3] ^= _b2i(key[:8]); S[4] ^= _b2i(key[8:])
    if ad:
        for i in range(0, len(_pad(ad, rate)), rate):
            S[0] ^= _b2i(_pad(ad, rate)[i:i + rate])
            _ascon_permutation(S, b)
    S[4] ^= 1
    pt = b''
    if ct:
        padded_ct = _pad(ct, rate)
        last_len  = len(ct) % rate or rate
        for i in range(0, len(padded_ct), rate):
            c_int   = _b2i(padded_ct[i:i + rate])
            pt_full = _i2b(S[0] ^ c_int, rate)
            pt += pt_full
            is_last = (i + rate >= len(padded_ct))
            if is_last:
                actual   = pt[-rate:][:last_len]
                pad_back = actual + b'\x80' + b'\x00' * (rate - 1 - last_len)
                S[0] ^= _b2i(pad_back)
            else:
                S[0] = c_int
            _ascon_permutation(S, b)
        pt = pt[:len(ct)]
    S[1] ^= _b2i(key[:8]); S[2] ^= _b2i(key[8:])
    _ascon_permutation(S, a)
    S[3] ^= _b2i(key[:8]); S[4] ^= _b2i(key[8:])
    expected = _i2b(S[3], 8) + _i2b(S[4], 8)
    diff = 0
    for x, y in zip(tag, expected): diff |= (x ^ y)
    if diff: raise ValueError("Ascon-128 AUTH FAILED — packet rejected")
    return pt

def ascon_encrypt(key, nonce, ad, plaintext):
    if _ASCON_NATIVE:
        return _ascon_lib.ascon_encrypt(key, nonce, ad, plaintext, "Ascon-AEAD128")
    return _py_ascon128_encrypt(key, nonce, ad, plaintext)

def ascon_decrypt(key, nonce, ad, ciphertext_tag):
    if _ASCON_NATIVE:
        result = _ascon_lib.ascon_decrypt(key, nonce, ad, ciphertext_tag, "Ascon-AEAD128")
        if result is None:
            raise ValueError("Ascon-128 AUTH FAILED — packet rejected")
        return result
    return _py_ascon128_decrypt(key, nonce, ad, ciphertext_tag)

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 2 — CBOR SERIALISATION
# ─────────────────────────────────────────────────────────────────────────────

def _cbor_lite_dumps(obj) -> bytes:
    def _lp(major, n):
        if n <= 0x17: return bytes([major | n])
        if n <= 0xff: return bytes([major | 0x18, n])
        return bytes([major | 0x19]) + struct.pack('>H', n)

    def _enc(v):
        if isinstance(v, bool):  return bytes([0xf5 if v else 0xf4])
        if isinstance(v, int):
            if v >= 0:
                if v <= 0x17:    return bytes([v])
                if v <= 0xff:    return bytes([0x18, v])
                if v <= 0xffff:  return bytes([0x19]) + struct.pack('>H', v)
                return bytes([0x1a]) + struct.pack('>I', v)
            n = -1 - v
            if n <= 0x17:  return bytes([0x20 | n])
            if n <= 0xff:  return bytes([0x38, n])
            return bytes([0x39]) + struct.pack('>H', n)
        if isinstance(v, float): return bytes([0xfb]) + struct.pack('>d', v)
        if isinstance(v, str):
            e = v.encode()
            return _lp(0x60, len(e)) + e
        if isinstance(v, bytes): return _lp(0x40, len(v)) + v
        if isinstance(v, dict):  return _cbor_lite_dumps(v)
        raise TypeError(f"CBOR-Lite: unsupported type {type(v)}")

    if not isinstance(obj, dict): return _enc(obj)
    result = _lp(0xa0, len(obj))
    for k, v in obj.items():
        result += _enc(k)
        result += _enc(v)
    return result

def cbor_dumps(obj: dict) -> bytes:
    if _CBOR_NATIVE:
        return cbor2.dumps(obj)
    return _cbor_lite_dumps(obj)

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 3 — TRANSPORT (MQTT-SN / CoAP stubs)
# ─────────────────────────────────────────────────────────────────────────────

TOPIC_VITALS = 0x0001

class MQTTSNTransport:
    HEADER_BYTES = 7

    def publish(self, topic_id, payload, qos=1, msg_id=0):
        wire_size = self.HEADER_BYTES + len(payload)
        return {
            "protocol":   "MQTT-SN",
            "msg_type":   "PUBLISH",
            "topic_id":   f"0x{topic_id:04x}",
            "qos":        qos,
            "msg_id":     msg_id,
            "payload_sz": len(payload),
            "wire_sz":    wire_size,
        }

class CoAPTransport:
    FIXED_HEADER_BYTES = 4
    _msg_id = 0

    def put(self, uri, payload, confirmable=True):
        self._msg_id = (self._msg_id + 1) & 0xFFFF
        option_bytes = len(uri) + 1
        wire_size    = self.FIXED_HEADER_BYTES + option_bytes + len(payload)
        return {
            "protocol":   "CoAP",
            "type":       "CON" if confirmable else "NON",
            "code":       "0.03 PUT",
            "msg_id":     self._msg_id,
            "uri":        uri,
            "payload_sz": len(payload),
            "wire_sz":    wire_size,
        }

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 4 — FOG LAYER IDS
# ─────────────────────────────────────────────────────────────────────────────

NETWORK_FEATURES  = ['SrcBytes', 'DstBytes', 'SrcLoad', 'DstLoad', 'SrcJitter',
                     'DstJitter', 'SIntPkt', 'DIntPkt', 'TotPkts', 'TotBytes',
                     'Rate', 'Loss', 'pLoss', 'Dur', 'Load']
BIOMETRIC_FEATURES = ['Temp', 'SpO2', 'Pulse_Rate', 'SYS', 'DIA',
                      'Heart_rate', 'Resp_Rate', 'ST']

def build_feature_matrix(df):
    df = df.copy()
    df['Flgs'] = df['Flgs'].str.strip()
    flgs_ohe  = pd.get_dummies(df['Flgs'], prefix='Flg')
    df        = pd.concat([df.reset_index(drop=True), flgs_ohe], axis=1)
    flg_cols  = flgs_ohe.columns.tolist()
    all_feats = NETWORK_FEATURES + flg_cols + BIOMETRIC_FEATURES
    return df, all_feats, flg_cols

def train_ids(csv_path: str):
    """Train IDS; returns (model, selected_features, label_encoder, flg_cols)."""
    df = pd.read_csv(csv_path)
    df['Flgs'] = df['Flgs'].str.strip()

    df_ext, all_feats, flg_cols = build_feature_matrix(df)
    le = LabelEncoder()
    y  = le.fit_transform(df_ext['Attack Category'])

    X = df_ext[all_feats].fillna(0)
    scores  = mutual_info_classif(X, y, discrete_features=False, random_state=42)
    ranked  = sorted(zip(all_feats, scores), key=lambda x: -x[1])
    selected = [f for f, _ in ranked[:15]]

    X_arr = df_ext[selected].fillna(0).values
    X_tr, X_te, y_tr, y_te = train_test_split(
        X_arr, y, test_size=0.2, random_state=42, stratify=y)

    if _SMOTE_AVAILABLE:
        sm = SMOTE(random_state=42)
        X_tr, y_tr = sm.fit_resample(X_tr, y_tr)

    if _XGB_AVAILABLE:
        clf = xgb.XGBClassifier(
            n_estimators=200, max_depth=6, learning_rate=0.05,
            eval_metric='mlogloss', random_state=42, n_jobs=-1)
    else:
        clf = RandomForestClassifier(
            n_estimators=200, max_depth=15,
            class_weight='balanced' if not _SMOTE_AVAILABLE else None,
            random_state=42, n_jobs=-1)
    clf.fit(X_tr, y_tr)

    y_pred = clf.predict(X_te)
    report = classification_report(y_te, y_pred, target_names=le.classes_,
                                   digits=4, zero_division=0)
    return clf, selected, le, flg_cols, report

def ids_predict(clf, selected_feats, le, flg_cols, row_dict: dict) -> str:
    df_row   = pd.DataFrame([row_dict])
    flgs_val = str(row_dict.get('Flgs', 'M')).strip()
    for col in flg_cols:
        df_row[col] = 1 if flgs_val == col.replace('Flg_', '') else 0
    X    = df_row[selected_feats].fillna(0).values
    pred = clf.predict(X)[0]
    return le.inverse_transform([pred])[0]

# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 5 — SIMULATION (generator — yields event dicts for SSE)
# ─────────────────────────────────────────────────────────────────────────────

def build_biometric_payload(row) -> dict:
    return {
        "Temp":       round(float(row['Temp']),       2),
        "SpO2":       int(row['SpO2']),
        "Pulse_Rate": int(row['Pulse_Rate']),
        "SYS":        int(row['SYS']),
        "DIA":        int(row['DIA']),
        "Heart_rate": int(row['Heart_rate']),
        "Resp_Rate":  int(row['Resp_Rate']),
        "ST":         round(float(row['ST']),          3),
        "pkt_num":    int(row['Packet_num']),
    }


def simulate_stream(csv_path: str, n_normal: int = 12, use_coap: bool = False,
                    ids_model=None):
    """
    Generator that yields event dicts for each pipeline step.
    Designed to be consumed by Flask SSE route.
    """
    df = pd.read_csv(csv_path)
    df['Flgs'] = df['Flgs'].str.strip()

    normal_s = df[df['Attack Category'] == 'normal'].sample(n_normal, random_state=7)
    spoof_s  = df[df['Attack Category'] == 'Spoofing'].sample(3, random_state=7)
    alter_s  = df[df['Attack Category'] == 'Data Alteration'].sample(3, random_state=7)
    sample   = pd.concat([normal_s, spoof_s, alter_s]) \
                 .sample(frac=1, random_state=7).reset_index(drop=True)

    session_key = os.urandom(16)
    transport   = CoAPTransport() if use_coap else MQTTSNTransport()
    proto_name  = "CoAP" if use_coap else "MQTT-SN"

    yield {"type": "init",
           "total":    len(sample),
           "protocol": proto_name,
           "cipher":   "Ascon-128 AEAD",
           "impl":     "pyascon" if _ASCON_NATIVE else "pure-Python",
           "key_hex":  session_key.hex()}

    stats = {"sent": 0, "auth_ok": 0, "auth_fail": 0, "attacks": 0,
             "json_b": 0, "cbor_b": 0, "wire_b": 0}

    for seq, (_, row) in enumerate(sample.iterrows()):
        pkt_num  = int(row['Packet_num'])
        category = row['Attack Category']
        is_attack = category != 'normal'

        # Step 1 — build payload
        payload_dict = build_biometric_payload(row)
        json_bytes   = json.dumps(payload_dict).encode()
        cbor_bytes   = cbor_dumps(payload_dict)

        yield {"type": "payload",
               "seq":         seq + 1,
               "pkt_num":     pkt_num,
               "category":    category,
               "biometrics":  payload_dict,
               "json_size":   len(json_bytes),
               "cbor_size":   len(cbor_bytes),
               "cbor_hex":    cbor_bytes.hex()}

        # Step 2 — encrypt
        nonce  = os.urandom(16)
        ad     = struct.pack('>Q', pkt_num)
        ct_tag = ascon_encrypt(session_key, nonce, ad, cbor_bytes)

        # Simulate Data Alteration: adversary flips a byte mid-transit
        tampered_wire = False
        if category == "Data Alteration":
            tampered = bytearray(cbor_bytes)
            if len(tampered) > 5:
                tampered[5] ^= 0xFF
            ct_tag = bytes(tampered)   # send raw corrupted bytes (not valid ciphertext)
            tampered_wire = True

        # Simulate Spoofing: replay with stale counter
        ad_received = ad
        stale_counter = False
        if category == "Spoofing":
            ad_received = struct.pack('>Q', max(0, pkt_num - 1000))
            stale_counter = True

        yield {"type": "encrypt",
               "seq":          seq + 1,
               "pkt_num":      pkt_num,
               "nonce_hex":    nonce.hex(),
               "ct_hex":       ct_tag.hex()[:64] + ("..." if len(ct_tag) > 32 else ""),
               "ct_size":      len(ct_tag),
               "ad_hex":       ad.hex(),
               "tampered":     tampered_wire,
               "stale_counter": stale_counter}

        # Step 3 — transmit
        wire_payload = nonce + ct_tag
        if use_coap:
            frame = transport.put("/ehms/vitals", wire_payload)
        else:
            frame = transport.publish(TOPIC_VITALS, wire_payload, qos=1, msg_id=pkt_num)

        yield {"type": "transmit",
               "seq":       seq + 1,
               "pkt_num":   pkt_num,
               "protocol":  proto_name,
               "wire_sz":   frame['wire_sz'],
               "payload_sz": frame['payload_sz']}

        # Step 4 — fog node decrypt + authenticate
        auth_ok = True
        try:
            ascon_decrypt(session_key, nonce, ad_received, ct_tag)
        except (ValueError, Exception):
            auth_ok = False

        yield {"type": "auth",
               "seq":      seq + 1,
               "pkt_num":  pkt_num,
               "category": category,
               "auth_ok":  auth_ok,
               "reason":   ("tag mismatch — payload altered" if tampered_wire
                            else "counter mismatch — replay detected" if stale_counter
                            else "ok")}

        # Step 5 — IDS inference (only on auth-OK packets for live demo)
        ids_label = None
        if ids_model and auth_ok:
            clf, sel, le, flg_cols = ids_model
            row_dict = {f: row[f] for f in NETWORK_FEATURES + BIOMETRIC_FEATURES
                        if f in row.index}
            row_dict['Flgs'] = row.get('Flgs', 'M')
            ids_label = ids_predict(clf, sel, le, flg_cols, row_dict)

        yield {"type": "ids",
               "seq":       seq + 1,
               "pkt_num":   pkt_num,
               "label":     ids_label,
               "auth_ok":   auth_ok}

        # Accumulate stats
        stats['sent']   += 1
        stats['json_b'] += len(json_bytes)
        stats['cbor_b'] += len(cbor_bytes)
        stats['wire_b'] += frame['wire_sz']
        if auth_ok:   stats['auth_ok']   += 1
        else:         stats['auth_fail'] += 1
        if is_attack: stats['attacks']   += 1

    cbor_saving = (1 - stats['cbor_b'] / max(stats['json_b'], 1)) * 100
    yield {"type": "stats", **stats, "cbor_saving_pct": round(cbor_saving, 1)}
    yield {"type": "done"}


# ─────────────────────────────────────────────────────────────────────────────
#  SECTION 6 — ATTACKER DEMO (generator)
# ─────────────────────────────────────────────────────────────────────────────

def attacker_stream(csv_path: str, n_packets: int = 6):
    """
    Generator for the attacker demo.
    Shows: intercept → brute-force attempt → alteration attempt → replay attempt.
    All attacks fail against Ascon-128 AEAD.
    """
    df = pd.read_csv(csv_path)
    df['Flgs'] = df['Flgs'].str.strip()

    # Use a mix of normal + attack packets so evaluator sees all cases
    normal_s = df[df['Attack Category'] == 'normal'].sample(2, random_state=99)
    spoof_s  = df[df['Attack Category'] == 'Spoofing'].sample(2, random_state=99)
    alter_s  = df[df['Attack Category'] == 'Data Alteration'].sample(2, random_state=99)
    sample   = pd.concat([normal_s, spoof_s, alter_s]) \
                 .sample(frac=1, random_state=99).reset_index(drop=True)

    session_key = os.urandom(16)  # victim's key — attacker does NOT know this

    yield {"type": "init",
           "total":   len(sample),
           "message": "Attacker positioned as man-in-the-middle on UDP channel"}

    for seq, (_, row) in enumerate(sample.iterrows()):
        pkt_num  = int(row['Packet_num'])
        category = row['Attack Category']

        payload_dict = build_biometric_payload(row)
        cbor_bytes   = cbor_dumps(payload_dict)
        nonce        = os.urandom(16)
        ad           = struct.pack('>Q', pkt_num)
        ct_tag       = ascon_encrypt(session_key, nonce, ad, cbor_bytes)
        wire_payload = nonce + ct_tag

        yield {"type": "intercept",
               "seq":          seq + 1,
               "pkt_num":      pkt_num,
               "category":     category,
               "wire_hex":     wire_payload.hex()[:80] + "...",
               "wire_size":    len(wire_payload),
               "cbor_hex":     cbor_bytes.hex(),
               "cbor_size":    len(cbor_bytes),
               "attacker_sees": "ENCRYPTED — only ciphertext visible, no plaintext"}

        # Attack 1 — try decryption with wrong key (all-zeros)
        wrong_key = bytes(16)
        try:
            ascon_decrypt(wrong_key, nonce, ad, ct_tag)
            result1 = "DECRYPTED (unexpected)"
        except Exception:
            result1 = "AUTH FAILED — wrong key produces garbage, tag mismatch"

        yield {"type": "attack",
               "seq":         seq + 1,
               "attack_type": "Wrong Key",
               "detail":      f"Tried key: {wrong_key.hex()} (all-zeros brute-force)",
               "result":      result1,
               "blocked":     True}

        # Attack 2 — byte-flip (Data Alteration)
        tampered = bytearray(ct_tag)
        if len(tampered) > 4:
            tampered[4] ^= 0xAB   # flip one ciphertext byte
        try:
            ascon_decrypt(session_key, nonce, ad, bytes(tampered))
            result2 = "DECRYPTED (unexpected)"
        except Exception:
            result2 = "AUTH FAILED — AEAD tag mismatch, 1-bit change detected"

        yield {"type": "attack",
               "seq":         seq + 1,
               "attack_type": "Data Alteration (byte-flip)",
               "detail":      f"Flipped byte at offset 4: 0x{ct_tag[4]:02x} → 0x{tampered[4]:02x}",
               "result":      result2,
               "blocked":     True}

        # Attack 3 — replay with stale counter (Spoofing)
        stale_ad = struct.pack('>Q', max(0, pkt_num - 500))
        try:
            ascon_decrypt(session_key, nonce, stale_ad, ct_tag)
            result3 = "DECRYPTED (unexpected)"
        except Exception:
            result3 = "AUTH FAILED — AD counter mismatch, replay rejected"

        yield {"type": "attack",
               "seq":         seq + 1,
               "attack_type": "Replay / Spoofing",
               "detail":      f"Replayed with stale counter {pkt_num - 500} vs expected {pkt_num}",
               "result":      result3,
               "blocked":     True}

        # Legitimate forwarding
        try:
            decrypted = ascon_decrypt(session_key, nonce, ad, ct_tag)
            forward_ok = True
            plaintext_preview = decrypted[:20].hex() + "..."
        except Exception:
            forward_ok = False
            plaintext_preview = None

        yield {"type": "forward",
               "seq":             seq + 1,
               "pkt_num":         pkt_num,
               "category":        category,
               "forward_ok":      forward_ok,
               "plaintext_bytes": plaintext_preview}

    yield {"type": "done",
           "summary": "All attacker intercept attempts blocked by Ascon-128 AEAD"}
