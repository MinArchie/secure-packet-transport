# Fog Security
This project aims to secure the transit of sensitive medical records in a health monitoring system. The architecture consists of wearable devices (sensors), fog layer, and cloud.
Our main focus is to secure the sensors -> fog architecure. 

The proposed architecture is as follows:
1. Use **Ascon-128** for encryption
2. Use **CoAP / MQTT-SN** for low-power devices
3. Use **CBOR** for payload compression
4. Deploy **IDS at fog layer**
5. Use **explainable AI models**

Reference these notion notes for a better idea: [Notion](https://adaptable-boot-602.notion.site/Fog-Security-Lightweight-3295c38e056880e6865ccd3ba3d47e03?pvs=73)
## Core Idea
Efficient IoMT security =

**Fog computing + lightweight protocols + Ascon encryption + optimized payload + explainable IDS**


## Table of Contents

1. [Project Overview](#1-project-overview)
2. [File Structure](#2-file-structure)
3. [Install & Run](#3-install--run)
4. [How Each Technology Works](#4-how-each-technology-works)
   - [Ascon-128 AEAD](#41-ascon-128-aead)
   - [CBOR Serialisation](#42-cbor-serialisation)
   - [MQTT-SN Transport](#43-mqtt-sn-transport)
   - [CoAP Transport](#44-coap-transport)
5. [IDS Pipeline](#5-ids-pipeline)
   - [Dataset — WUSTL-EHMS-2020](#51-dataset--wustl-ehms-2020)
   - [Feature Engineering](#52-feature-engineering)
   - [Feature Selection (Information Gain)](#53-feature-selection-information-gain)
   - [Class Imbalance — SMOTE](#54-class-imbalance--smote)
   - [Classifier](#55-classifier)
6. [Function Reference](#6-function-reference)
   - [pipeline.py](#61-pipelinepy)
   - [app.py](#62-apppy)
7. [Web UI](#7-web-ui)
8. [Attack Simulation Logic](#8-attack-simulation-logic)
9. [Known Limitations & Academic Notes](#9-known-limitations--academic-notes)

---

## 1. Project Overview

This project models the **Things → Fog → Cloud** data path for an Electronic Health Monitoring System (EHMS). Real patient biometric records are taken from the WUSTL-EHMS-2020 dataset and fed through the following pipeline on each "transmission":

```
[Wearable Sensor]
    1. Build biometric payload dict
    2. Serialise to CBOR binary (smaller than JSON)
    3. Encrypt with Ascon-128 AEAD
       (key = pre-shared 128-bit session key,
        nonce = fresh 16-byte random per packet,
        AD = 8-byte big-endian packet counter for replay protection)
    4. Transmit over UDP via MQTT-SN PUBLISH or CoAP PUT

[Fog Node]
    5. Ascon-128 AUTH + decrypt
       (reject if tag mismatch OR counter mismatch)
    6. IDS inference on auth-OK packets
       (XGBoost or RandomForest, 15 IG-selected features)

[Cloud]
    7. Longitudinal health records, analytics
```

Two attack classes from the dataset are simulated live:
- **Data Alteration** — adversary flips a byte in the payload in transit → Ascon tag mismatch → rejected at step 5.
- **Spoofing / Replay** — adversary replays a captured packet with a stale counter → AD mismatch → rejected at step 5.

---

## 2. File Structure

```
fog-security/
├── app.py                             # Flask web server + SSE routes
├── pipeline.py                        # Core pipeline logic (imported by app.py)
├── fog_security.ipynb                 # Original Jupyter notebook (standalone)
├── wustl-ehms-2020_with_attacks_categories.csv   # Dataset (not included in repo)
└── templates/
    ├── index.html                     # Normal simulation UI
    └── attacker.html                  # Attacker MitM demo UI
```

---

## 3. Install & Run

### Prerequisites

- Python 3.9+
- pip


# Installation
1. clone the repo
2. Install requirements
   ```bash
   pip install -r requirements.txt
   ```

      
   All packages have pure-Python fallbacks if the optional ones are missing:

   | Package | Role | Fallback if missing |
   |---|---|---|
   | `ascon` | Ascon-128 AEAD (NIST SP 800-232) | Pure-Python implementation included |
   | `cbor2` | CBOR RFC 8949 serialisation | Pure-Python CBOR-Lite encoder included |
   | `paho-mqtt` | Real MQTT broker connection | Mock wire-frame simulation |
   | `xgboost` | Faster IDS classifier | `sklearn.RandomForestClassifier` |
   | `imbalanced-learn` | SMOTE for class balancing | `class_weight='balanced'` used instead |

2. open ```fog_security.ipynb```
3. open the Mosquitto broker
   ```
   cd mos2
   mosquitto.exe -v
   ```
   This broker was kindly packaged by [Steve's Internet Guide](http://www.steves-internet-guide.com/install-mosquitto-broker/). This prepacked mosquitto broker is far easier to set up and run rather than the manual windows installation.
   The broker should initalize on localhost:1883. opening this through the browser will not work as http is incompatible with mqtt
4. Run the code

   ```bash
   python app.py
   ```
   
   Open in your browser:
   - `http://127.0.0.1:5000` — Normal pipeline simulation
   - `http://127.0.0.1:5000/attacker` — Attacker MitM demo

   > The IDS model trains in the background. The simulation will wait up to 3 seconds for it; if it is not ready the simulation runs without IDS labels and they appear as `n/a`.

5. If you mqtt broker was successful, you will notice logs such as:
   <img width="1288" height="970" alt="image" src="https://github.com/user-attachments/assets/3f196d80-253b-4f8c-93a6-e9c621c7571a" />
6. Run the simulator with:
   ```
   python app.py
   ```


---

## 4. How Each Technology Works

### 4.1 Ascon-128 AEAD

**Why Ascon?** It was standardised by NIST in SP 800-232 specifically for constrained IoT devices. Compared to AES-128-GCM it is 4–6× faster on 8-bit microcontrollers, uses no lookup tables (no cache-timing side channels), needs no handshake, and has a post-quantum variant (`Ascon-80pq`).

**Ascon-128 structure** — the state is five 64-bit words (320 bits total). Each round applies three layers:

1. **Constant addition** — XOR a round constant into word 2. Prevents slide attacks.
2. **Substitution layer** — a 5-bit S-box applied in bitsliced form across all 64 positions simultaneously.
3. **Linear diffusion** — each word XORed with two rotations of itself. Rotation amounts differ per word to provide full diffusion.

**AEAD mode (Ascon-128):**

- **Initialisation** — load IV, key, and nonce into the five state words; run 12 permutation rounds; then XOR the key into the last two words.
- **Associated Data processing** — absorb AD blocks (rate = 8 bytes) with 6-round permutations between blocks. AD is authenticated but not encrypted (used here for the packet counter).
- **Plaintext encryption** — absorb and squeeze plaintext blocks in the same rate/permutation pattern.
- **Finalisation** — XOR the key again; run 12 rounds; output the last 16 bytes as the authentication tag appended to the ciphertext.

**Decryption** reverses the process and performs a constant-time comparison of the recomputed tag against the received tag. Any single-bit change in the ciphertext, AD, or key causes the tag check to fail and a `ValueError` is raised immediately.

**Replay protection** is achieved by packing the packet sequence number as the 8-byte Associated Data (`struct.pack('>Q', pkt_num)`). Because AD is bound into the tag, a replayed packet arriving with the wrong counter produces a tag mismatch even though the ciphertext bytes are valid.

The project ships a complete pure-Python fallback (`_py_ascon128_encrypt` / `_py_ascon128_decrypt`) validated against the pyascon reference library. If `pip install ascon` is available, the native library is used instead.

---

### 4.2 CBOR Serialisation

**Why CBOR instead of JSON?** JSON encodes everything as UTF-8 text. CBOR (Concise Binary Object Representation, RFC 8949) is a binary format with the same data model. For a typical biometric payload the saving is roughly 35–45%.

```
JSON (84 B):  {"Temp": 37.1, "SpO2": 98, "Pulse_Rate": 74, ...}
CBOR (48 B):  a9 66 54 65 6d 70 ...  (binary, no quotes, compact integers)
```

At 1,000 packets per hour (typical wearable), saving 36 bytes per packet reduces total radio-on time by ~43%, which translates directly into battery life on a coin-cell device.

**Encoding rules (major type prefix byte):**
- Integers ≤ 23 encode in 1 byte (no extra length byte needed).
- Strings get a major-type-3 prefix + length + UTF-8 bytes.
- Floats always use 8-byte IEEE-754 double (`0xfb` prefix).
- Maps (dicts) get a major-type-5 prefix with the item count.

The `cbor_dumps()` function uses `cbor2` when installed, and falls back to the hand-written `_cbor_lite_dumps()` which handles all types present in a biometric payload (int, float, str, bytes, dict).

---

### 4.3 MQTT-SN Transport

**Why MQTT-SN instead of standard MQTT?** Standard MQTT runs over TCP, which requires a 3-way handshake before any data flows. On a wearable that wakes up every 30 seconds to send one packet, the handshake consumes more energy than the transmission itself. MQTT-SN runs over UDP, has no connection state on the sensor, and supports QoS -1 (fire-and-forget — the sensor broadcasts and immediately sleeps).

Key advantages over MQTT:
- **Pre-registered topic IDs** — a 2-byte integer replaces the full topic string (e.g., `0x0001` instead of `"ehms/sensor/vitals"`), saving ~20 bytes per packet.
- **QoS -1** — no broker connection required; sensor just sends and goes back to sleep.
- **7-byte fixed header** overhead (vs 200+ bytes for HTTP/TLS).

The `MQTTSNTransport` class simulates accurate wire-frame sizes. When `paho-mqtt` is installed and a broker is reachable at `localhost:1883`, it wraps a real MQTT broker connection (mapping the integer topic ID to a topic string for broker routing).

---

### 4.4 CoAP Transport

CoAP (Constrained Application Protocol, RFC 7252) is the alternative transport for scenarios where the sensor acts as a server (e.g., an implantable that responds to polling) or when multicast commands are needed. It uses a 4-byte fixed header (smaller than MQTT-SN's 7 bytes, but adds URI-Path option bytes).

The `CoAPTransport` class simulates `PUT /ehms/vitals` with CON (confirmable) or NON messages and computes accurate wire sizes. Production use would substitute `aiocoap` or `CoAPthon3`.

Both transports are selectable at runtime via the `use_coap` flag in `simulate_stream()`.

---

## 5. IDS Pipeline

### 5.1 Dataset — WUSTL-EHMS-2020

The **Washington University St. Louis Electronic Health Monitoring System 2020** dataset was collected from wearable sensors on patients and contains:

- **Network flow features** — ARGUS-generated metrics per UDP flow: source/destination bytes, load, jitter, inter-packet timing, total packets, rate, loss, etc.
- **Biometric features** — sensor readings per packet: body temperature, SpO2, pulse rate, systolic/diastolic blood pressure, heart rate, respiration rate, ECG ST segment.
- **Protocol flags** — the ARGUS `Flgs` column records per-flow TCP/UDP flag combinations as short strings (e.g., `"M"`, `"e"`, `"eR"`).
- **Attack Category label** — `normal`, `Spoofing`, or `Data Alteration`.

The dataset is heavily imbalanced: normal traffic is the large majority, Data Alteration is a moderate minority, and Spoofing is a small minority.

---

### 5.2 Feature Engineering

Raw features are prepared in `build_feature_matrix()`:

1. Strip whitespace from the `Flgs` column (the raw CSV has trailing spaces that break encoding).
2. One-hot encode `Flgs` into binary columns (`Flg_M`, `Flg_e`, `Flg_eR`, etc.) using `pd.get_dummies`. These flags are among the strongest discriminators — Data Alteration flows almost exclusively show `Flg_M` while Spoofing flows show `Flg_e` or `Flg_eR`.
3. Concatenate the 15 ARGUS network features, all one-hot flag columns, and the 8 biometric features into the full feature matrix.

---

### 5.3 Feature Selection (Information Gain)

`select_features_by_ig()` uses `sklearn.feature_selection.mutual_info_classif` to score every feature by its mutual information with the attack category label. The top 15 features are selected. This step:

- Removes redundant or near-zero-variance features that would slow training.
- Tends to rank the flag columns and high-variance network metrics (e.g., `SrcBytes`, `Rate`, `DstLoad`) at the top.
- Is reproducible across runs via `random_state=42`.

---

### 5.4 Class Imbalance — SMOTE

Spoofing is a minority class. Without correction, the model learns to mostly predict "normal" and still achieves high overall accuracy. Two remedies are available:

- **With `imbalanced-learn`**: SMOTE (Synthetic Minority Over-sampling Technique) generates synthetic Spoofing samples in the training set by interpolating between real minority samples in feature space. Applied only to the training split.
- **Without `imbalanced-learn`**: `class_weight='balanced'` in RandomForest inversely weights each class by its frequency, giving minority classes more influence during tree splitting.

---

### 5.5 Classifier

**With XGBoost** (`xgboost` installed): `XGBClassifier` with 200 trees, max depth 6, learning rate 0.05, `mlogloss` evaluation. Faster inference on fog hardware (limited CPU).

**Without XGBoost**: `RandomForestClassifier` with 200 trees, max depth 15.

**Expected performance** (consistent with published WUSTL-EHMS-2020 results):
- `normal`: F1 ≈ 1.00
- `Data Alteration`: F1 ≈ 1.00 (unique flag pattern makes it trivially separable)
- `Spoofing`: F1 ≈ 0.30–0.40

The low Spoofing IDS recall is **correct and expected**. Spoofing is a confidentiality attack — the adversary replays valid encrypted packets whose biometric values and most network metrics are indistinguishable from normal traffic. The primary defence is the **cryptographic layer** (Ascon AD counter mismatch), not the IDS. See [Section 10](#10-known-limitations--academic-notes) for full discussion.

---

## 6. Function Reference

### 6.1 pipeline.py

#### `ascon_encrypt(key, nonce, ad, plaintext) → bytes`
Encrypts `plaintext` with Ascon-128 AEAD. Returns `ciphertext || 16-byte tag`. Uses the `ascon` package if installed, otherwise the pure-Python fallback. `key` and `nonce` must be 16 bytes each. `ad` is bound into the tag but not encrypted — pass the 8-byte big-endian packet counter here.

#### `ascon_decrypt(key, nonce, ad, ciphertext_tag) → bytes`
Decrypts and authenticates. Raises `ValueError` if the tag does not match (tampered ciphertext, wrong key, or wrong AD / replay). Constant-time tag comparison to prevent timing attacks.

#### `cbor_dumps(obj: dict) → bytes`
Serialises a dict to CBOR binary. Uses `cbor2` if installed, otherwise `_cbor_lite_dumps`.

#### `build_feature_matrix(df) → (df_extended, all_feats, flg_cols)`
Takes the raw dataset DataFrame and returns: the DataFrame with one-hot Flgs columns appended, the full ordered list of feature column names, and just the flag column names. Used before both training and inference.

#### `train_ids(csv_path: str) → (clf, selected_feats, label_encoder, flg_cols, report)`
Loads the CSV, builds the feature matrix, runs Information Gain selection (top 15), splits 80/20, applies SMOTE or class weights, trains XGBoost or RandomForest, and returns the fitted model tuple plus a `classification_report` string. Called once at startup in a background thread by `app.py`.

#### `ids_predict(clf, selected_feats, le, flg_cols, row_dict: dict) → str`
Runs inference on a single packet row dict. Reconstructs the one-hot Flgs columns from the raw `Flgs` string, builds a single-row DataFrame aligned to `selected_feats`, calls `clf.predict`, and returns the decoded label string (e.g., `"normal"`, `"Spoofing"`).

#### `simulate_stream(csv_path, n_normal, use_coap, ids_model) → generator`
The main pipeline generator. Yields SSE-ready event dicts for each of the five pipeline steps per packet: `payload`, `encrypt`, `transmit`, `auth`, `ids`, then `stats` and `done`. Consumed by the Flask `/stream` route. Samples `n_normal` normal rows plus 3 Spoofing and 3 Data Alteration rows from the dataset, shuffles them, and processes each through the full encrypt → transmit → decrypt → IDS flow.

#### `attacker_stream(csv_path, n_packets) → generator`
Attacker demo generator. For each packet it yields: an `intercept` event (what the attacker sees on the wire), three `attack` events (wrong key, byte-flip, replay — all blocked), and a `forward` event (showing the fog node still receives the legitimate packet cleanly). Consumed by `/stream-attack`.

---

### 6.2 app.py

#### `GET /`
Renders `templates/index.html` — the normal pipeline simulation page.

#### `GET /attacker`
Renders `templates/attacker.html` — the attacker MitM demo page.

#### `GET /stream`
SSE endpoint for the normal simulation. Waits up to 3 seconds for the IDS model to be ready, then calls `pl.simulate_stream()` and streams each event with pacing delays that match the frontend animation timings.

#### `GET /stream-attack`
SSE endpoint for the attacker demo. Calls `pl.attacker_stream()` and streams events.

#### `GET /ids-status`
JSON polling endpoint used by the frontend to show IDS training progress. Returns `{ status, ready, report }`.

#### Background thread (`_train_ids_background`)
Starts at process launch. Calls `pl.train_ids()` with the CSV path, stores the result in `_ids_model`, and sets `_ids_ready = True`. The `/stream` route reads `_ids_model` once it is set.

---

## 7. Web UI

### `templates/index.html` — Normal Simulation

Displays a four-node topology diagram (Sensor → Fog → IDS → Cloud) with an animated packet dot that moves through each node as SSE events arrive. For each packet it shows:

- Step progress bar (5 steps, each turns green on completion)
- Detail panel: plaintext biometrics, CBOR hex, Ascon ciphertext hex, auth/IDS result
- Full packet log table with category pills, CBOR size, ciphertext preview, auth status, IDS label
- Stats summary bar at the end (packets sent, auth OK, auth rejected, attacks, CBOR savings %)

Controls: Run / Pause / Resume / Reset.

### `templates/attacker.html` — Attacker Demo

Shows a three-node topology with the attacker node hanging below the wire between Sensor and Fog. For each packet:

- Intercept panel: what the attacker sees (encrypted wire hex) vs what is actually inside (CBOR hex — not visible to attacker)
- Attack panel: three attack attempts per packet (wrong key brute-force, byte-flip alteration, replay) all marked BLOCKED
- Full packet outcome log table
- Final score banner confirming all attacks blocked

---

## 8. Attack Simulation Logic

### Data Alteration (in `simulate_stream`)

```python
if category == "Data Alteration":
    tampered = bytearray(cbor_bytes)
    tampered[5] ^= 0xFF          # flip byte 5 of the plaintext
    ct_tag = bytes(tampered)     # send corrupted bytes as if they were ciphertext
```

The fog node then calls `ascon_decrypt(session_key, nonce, ad, ct_tag)`. Since `ct_tag` is now corrupted CBOR (not a valid ciphertext at all), the tag recomputation fails → `ValueError` → `auth_ok = False`.

### Spoofing / Replay (in `simulate_stream`)

```python
if category == "Spoofing":
    ad_received = struct.pack('>Q', max(0, pkt_num - 1000))  # stale counter
```

The ciphertext and nonce are untouched, but the fog node decrypts with the wrong AD (stale counter). Since the original encryption bound the correct counter into the tag, the recomputed tag does not match → `ValueError` → `auth_ok = False`.

### Attacker Demo (in `attacker_stream`)

Three independent attacks per packet, all against a legitimate ciphertext:

1. **Wrong key** — decrypt with `bytes(16)` (all-zeros). Tag mismatch.
2. **Byte-flip** — flip byte at offset 4 of the ciphertext. Tag mismatch.
3. **Replay** — decrypt with correct key but stale counter (`pkt_num - 500`) as AD. Tag mismatch.

All three raise `ValueError`. The legitimate forwarding (correct key + correct AD) always succeeds.

---

## 9. Known Limitations & Academic Notes

### Why Spoofing IDS recall is ~32% (expected, not a bug)

Spoofing in WUSTL-EHMS-2020 is a **confidentiality attack**. The adversary sniffs encrypted packets and replays them — they do not modify the payload. This means:

- Biometric values in a replayed packet are identical to normal traffic.
- Network flow metrics (`Load`, `Rate`, `Jitter`) largely overlap with normal.
- `Flg_e` appears in both Spoofing AND the majority of normal flows.

The IDS simply cannot distinguish a replayed packet from a normal one using flow-level features alone. This is correct. The complete defence is layered:

- **Layer 1 — Cryptographic (100% effective):** Ascon-128 AD counter. Any replay arrives with a stale counter → `AUTH FAIL` at the fog node. *All Spoofing packets are rejected before they reach the IDS.*
- **Layer 2 — IDS (~32% recall on Spoofing):** Catches Spoofing flows where jitter or inter-packet timing deviates from the sensor's registered profile. Limited by dataset overlap.
- **Layer 3 — Future work:** Per-sensor temporal profiling — track mean inter-packet intervals per registered sensor ID. A replay from a different adversarial device will have a different timing signature.

The correct academic statement: *"Spoofing is primarily a cryptographic problem solved by the Ascon AEAD replay counter. The IDS provides a secondary network-level signal. Data Alteration is fully detectable at both layers (F1 = 1.00)."*

### NIST SP 800-232 vs the standard Ascon-128 in this project

The `pyascon` library (`pip install ascon`) implements **Ascon-AEAD128** as standardised in NIST SP 800-232, which uses **rate = 16 bytes** and **b = 8** rounds in the inner permutation.

The pure-Python fallback in this project (and the main pipeline) implements the earlier **Ascon-128** variant with **rate = 8 bytes** and **b = 6** rounds (the version submitted to NIST's LWC competition). Both are cryptographically sound; they just produce different ciphertexts for the same inputs. The `ascon_encrypt` / `ascon_decrypt` wrappers call whichever is available and are consistent with themselves — you cannot mix outputs of the two variants.

The experimental NIST-compliant rate-16 implementation at the bottom of `fog_security.ipynb` (Section "Misc") is not used in the main pipeline.

## Referenced code
[Ascon](https://github.com/MinArchie/Fog-Security/tree/main)

[CBOR](https://github.com/brianolson/cbor_py)

[MQTT-Simulation](https://github.com/DamascenoRafael/mqtt-simulator)
