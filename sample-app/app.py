"""
Sample Flask Application
This is a deliberately simple web app used as the scan target for the
DevSecOps pipeline. It demonstrates secure coding practices that the
pipeline validates on every commit.

Author: Sunny Bhardwaj
"""

import os
from flask import Flask, request, jsonify

app = Flask(__name__)

# Secrets loaded from environment — never hardcoded
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY", "")


@app.route("/")
def home():
    return jsonify({"status": "ok", "service": "sample-app"})


@app.route("/health")
def health():
    return jsonify({"status": "healthy"}), 200


@app.route("/echo", methods=["POST"])
def echo():
    """Echo endpoint with input validation."""
    data = request.get_json(silent=True)
    if not data or "message" not in data:
        return jsonify({"error": "Invalid input"}), 400

    # Input validation — limit message length
    message = str(data["message"])[:500]
    return jsonify({"echo": message})


if __name__ == "__main__":
    # Debug mode disabled for security
    app.run(host="127.0.0.1", port=5000, debug=False)
