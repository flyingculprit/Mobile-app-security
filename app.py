from flask import Flask, render_template, request
from androguard.misc import AnalyzeAPK
import os
import re

from analyzer.permissions import detect_dangerous_permissions
from analyzer.manifest import exported_components
from analyzer.secrets import detect_secrets
from analyzer.network import detect_insecure_urls

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER


# -------------------------
# API KEY DETECTION
# -------------------------
def detect_api_keys(strings):

    api_keys = []

    google_api = r"AIza[0-9A-Za-z\-_]{35}"
    firebase = r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"
    stripe = r"sk_live_[0-9a-zA-Z]{24}"

    for s in strings:

        if re.search(google_api, s):
            api_keys.append(("Google API Key", s))

        if re.search(firebase, s):
            api_keys.append(("Firebase Key", s))

        if re.search(stripe, s):
            api_keys.append(("Stripe Secret Key", s))

    return api_keys


@app.route("/", methods=["GET", "POST"])
def index():

    if request.method == "POST":

        apk_file = request.files["apk"]

        apk_path = os.path.join(app.config["UPLOAD_FOLDER"], apk_file.filename)

        apk_file.save(apk_path)

        apk, d, dx = AnalyzeAPK(apk_path)

        # -------------------------
        # PERMISSIONS
        # -------------------------
        permissions = apk.get_permissions()

        dangerous_perms = detect_dangerous_permissions(permissions)

        # -------------------------
        # EXPORTED COMPONENTS
        # -------------------------
        exported = exported_components(apk)

        # -------------------------
        # STRINGS
        # -------------------------
        strings = []

        for s in dx.get_strings():
            strings.append(str(s))

        # -------------------------
        # SECURITY CHECKS
        # -------------------------
        secrets = detect_secrets(strings)

        insecure_urls = detect_insecure_urls(strings)

        api_keys = detect_api_keys(strings)

        # -------------------------
        # HANDLE MANIFEST ERROR
        # -------------------------
        exported_count = 0

        if isinstance(exported, dict) and "error" not in exported:

            for v in exported.values():
                exported_count += len(v)

        # -------------------------
        # RISK SCORE
        # -------------------------
        risk_score = (
            len(dangerous_perms)
            + exported_count
            + len(secrets)
            + len(api_keys)
        )

        # convert to percentage (max 10 for example)
        score = min(risk_score * 10, 100)

        if risk_score > 6:
            risk = "HIGH 🔴"
            score_class = "score-high"

        elif risk_score > 3:
            risk = "MEDIUM 🟠"
            score_class = "score-medium"

        else:
            risk = "LOW 🟢"
            score_class = "score-low"

        return render_template(
            "report.html",
            permissions=permissions,
            dangerous=dangerous_perms,
            exported=exported,
            secrets=secrets,
            insecure_urls=insecure_urls,
            api_keys=api_keys,
            risk=risk,
            score=score,
            score_class=score_class
        )
    return render_template("index.html")


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    # allow multi-threaded uploads and access from ngrok
    app.run(host="0.0.0.0", port=port, debug=True, threaded=True)