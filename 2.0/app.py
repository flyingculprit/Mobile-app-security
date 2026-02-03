from flask import Flask, render_template, request
from androguard.misc import AnalyzeAPK
import os

from analyzer.permissions import detect_dangerous_permissions
from analyzer.manifest import exported_components
from analyzer.secrets import detect_secrets
from analyzer.network import detect_insecure_urls

app = Flask(__name__)
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        apk_file = request.files["apk"]
        apk_path = os.path.join(UPLOAD_FOLDER, apk_file.filename)
        apk_file.save(apk_path)

        apk, d, dx = AnalyzeAPK(apk_path)

        permissions = apk.get_permissions()
        dangerous_perms = detect_dangerous_permissions(permissions)

        exported = exported_components(apk)

        strings = []
        for method in dx.get_strings():
            strings.append(str(method))

        secrets = detect_secrets(strings)
        insecure_urls = detect_insecure_urls(strings)

        risk_score = len(dangerous_perms) + len(exported) + len(secrets)

        if risk_score > 5:
            risk = "HIGH 🔴"
        elif risk_score > 2:
            risk = "MEDIUM 🟠"
        else:
            risk = "LOW 🟢"

        return render_template(
            "report.html",
            permissions=permissions,
            dangerous=dangerous_perms,
            exported=exported,
            secrets=secrets,
            insecure_urls=insecure_urls,
            risk=risk
        )

    return render_template("index.html")

if __name__ == "__main__":
    app.run(debug=True)
