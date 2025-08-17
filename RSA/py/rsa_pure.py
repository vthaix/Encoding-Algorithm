from flask import Flask, render_template, request, jsonify
import secrets, math

app = Flask(__name__, template_folder="../view")

# ------------------ RSA core ------------------
def egcd(a, b):
    if b == 0:
        return (a, 1, 0)
    g, x1, y1 = egcd(b, a % b)
    return (g, y1, x1 - (a // b) * y1)

def modinv(a, m):
    g, x, _ = egcd(a, m)
    if g != 1:
        raise ValueError("Không tồn tại nghịch đảo modulo")
    return x % m

def is_probable_prime(n, k=32):
    if n < 2:
        return False
    small_primes = [2,3,5,7,11,13,17,19,23,29,31]
    if n in small_primes:
        return True
    if any(n % p == 0 for p in small_primes):
        return False
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2
    for _ in range(k):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for __ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True

def gen_prime(bits):
    while True:
        p = secrets.randbits(bits) | (1 << (bits - 1)) | 1
        if is_probable_prime(p):
            return p

def generate_keypair(bits=1024, e=65537):
    half = bits // 2
    while True:
        p = gen_prime(half)
        q = gen_prime(bits - half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        if math.gcd(e, phi) == 1:
            d = modinv(e, phi)
            return (e, n), (d, n)

def bytes_to_int(b): return int.from_bytes(b, "big")
def int_to_bytes(x, length): return x.to_bytes(length, "big")
def str_to_bytes(s): return s.encode("utf-8")
def bytes_to_str(b): return b.decode("utf-8", errors="strict")

def max_plain_block_len(n): return (n.bit_length() - 1) // 8
def chunk_bytes(data, size):
    for i in range(0, len(data), size):
        yield data[i:i+size]

def encrypt_message(msg, pub):
    e, n = pub
    m_bytes = str_to_bytes(msg)
    k = max_plain_block_len(n)
    l = (n.bit_length() + 7) // 8
    ct_blocks = []
    for block in chunk_bytes(m_bytes, k):
        m = bytes_to_int(block)
        c = pow(m, e, n)
        ct_blocks.append(int_to_bytes(c, l))
    return b"".join(ct_blocks)

def decrypt_message(ct_bytes, priv):
    d, n = priv
    l = (n.bit_length() + 7) // 8
    pt_blocks = []
    for block in chunk_bytes(ct_bytes, l):
        c = bytes_to_int(block)
        m = pow(c, d, n)
        pt_blocks.append(int_to_bytes(m, (m.bit_length() + 7) // 8 or 1))
    return bytes_to_str(b"".join(pt_blocks))

# ------------------ Khởi tạo ------------------
PUB, PRIV = generate_keypair(1024)

@app.route("/")
def index():
    return render_template("test.html")

@app.route("/encode", methods=["POST"])
def encode():
    data = request.get_json()
    text = data.get("text", "")
    cipher = encrypt_message(text, PUB).hex()
    return jsonify({"cipher": cipher})

@app.route("/decode", methods=["POST"])
def decode():
    data = request.get_json()
    cipher_hex = data.get("cipher", "")
    try:
        pt = decrypt_message(bytes.fromhex(cipher_hex), PRIV)
        return jsonify({"plain": pt})
    except Exception as e:
        return jsonify({"error": str(e)}), 400

if __name__ == "__main__":
    app.run(debug=True, port = 5001)
