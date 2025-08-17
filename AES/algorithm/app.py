import os
from flask import Flask, render_template, request, jsonify
from aes import encrypt_aes, decrypt_aes

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

app = Flask(__name__, template_folder=TEMPLATE_DIR)

@app.route("/")
def index():
    return render_template("view.html")

@app.route("/encrypt", methods=["POST"])
def encrypt():
    data = request.json
    plaintext = data.get("plaintext", "")
    password = data.get("password", "")
    encrypted_text = encrypt_aes(plaintext, password)
    return jsonify({"result": encrypted_text})

@app.route("/decrypt", methods=["POST"])
def decrypt():
    data = request.json
    ciphertext = data.get("ciphertext", "")
    password = data.get("password", "")
    try:
        decrypted_text = decrypt_aes(ciphertext, password)
        return jsonify({"result": decrypted_text})
    except Exception:
        return jsonify({"error": "Giải mã thất bại. Kiểm tra mật khẩu hoặc bản mã."}), 400

if __name__ == "__main__":
    app.run(debug=True)
