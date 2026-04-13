"""
app.py  —  Flask web server for the Fog Security demo.
  /            Main simulation — packet flow with encryption visualization
  /attacker    Attacker demo — MitM sniffing attempts (all blocked)
  /stream      SSE: normal simulation events
  /stream-attack  SSE: attacker demo events
  /train-status   SSE: IDS training progress
"""

import json, time, threading, os
from pathlib import Path
from flask import Flask, render_template, Response, stream_with_context

import pipeline as pl

app = Flask(__name__)

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR = Path(__file__).parent
CSV_PATH = str(BASE_DIR / "wustl-ehms-2020_with_attacks_categories.csv")

# ── IDS model (trained once at startup in a background thread) ────────────────
_ids_model = None          # (clf, selected_feats, le, flg_cols)
_ids_report = ""
_ids_ready  = False
_ids_status = "not_started"
_ids_lock   = threading.Lock()

def _train_ids_background():
    global _ids_model, _ids_report, _ids_ready, _ids_status
    try:
        _ids_status = "training"
        clf, sel, le, flg_cols, report = pl.train_ids(CSV_PATH)
        with _ids_lock:
            _ids_model  = (clf, sel, le, flg_cols)
            _ids_report = report
            _ids_ready  = True
            _ids_status = "ready"
    except Exception as e:
        _ids_status = f"error: {e}"

threading.Thread(target=_train_ids_background, daemon=True).start()


# ── SSE helper ─────────────────────────────────────────────────────────────────
def sse_event(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/attacker")
def attacker():
    return render_template("attacker.html")


@app.route("/stream")
def stream():
    use_coap = False   # MQTT-SN by default; ?coap=1 switches

    def generate():
        # Wait up to 3s for IDS if it's almost ready
        waited = 0
        while not _ids_ready and _ids_status == "training" and waited < 3:
            time.sleep(0.5)
            waited += 0.5

        ids_arg = _ids_model if _ids_ready else None

        for event in pl.simulate_stream(CSV_PATH, n_normal=12,
                                        use_coap=use_coap, ids_model=ids_arg):
            yield sse_event(event)
            # Slight pacing so the animation has time to render
            etype = event.get("type")
            if etype == "payload":     time.sleep(0.25)
            elif etype == "encrypt":   time.sleep(0.35)
            elif etype == "transmit":  time.sleep(0.30)
            elif etype == "auth":      time.sleep(0.25)
            elif etype == "ids":       time.sleep(0.20)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/stream-attack")
def stream_attack():
    def generate():
        for event in pl.attacker_stream(CSV_PATH, n_packets=6):
            yield sse_event(event)
            etype = event.get("type")
            if etype == "intercept": time.sleep(0.5)
            elif etype == "attack":  time.sleep(0.6)
            elif etype == "forward": time.sleep(0.4)

    return Response(stream_with_context(generate()),
                    mimetype="text/event-stream",
                    headers={"Cache-Control": "no-cache",
                             "X-Accel-Buffering": "no"})


@app.route("/ids-status")
def ids_status():
    """Polling endpoint so the UI can show IDS training progress."""
    return json.dumps({
        "status":  _ids_status,
        "ready":   _ids_ready,
        "report":  _ids_report if _ids_ready else None
    }), 200, {"Content-Type": "application/json"}


if __name__ == "__main__":
    print("=== Fog Security Demo ===")
    print(f"  CSV : {CSV_PATH}")
    print("  IDS training in background...")
    print("  Open: http://127.0.0.1:5000")
    print("        http://127.0.0.1:5000/attacker")
    app.run(debug=False, threaded=True, port=5000)
