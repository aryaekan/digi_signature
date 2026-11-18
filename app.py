import os
import base64
from flask import Flask, render_template, request, redirect, url_for
import qrcode
import io
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

app = Flask(__name__)

# Simulasi Database Penyimpanan Dokumen & Kriptografi
document_db = {}

# Generate Key Pair RSA Global untuk Prototype
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
public_key = private_key.public_key()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/sign', methods=['POST'])
def sign_document():
    doc_id = request.form.get('doc_id')
    doc_content = request.form.get('doc_content')
    
    doc_bytes = doc_content.encode('utf-8')
    
    # 1. Buat Hash SHA-256
    sha256_hash = hashlib.sha256(doc_bytes).hexdigest()
    
    # 2. Buat Digital Signature menggunakan Private Key (RSA)
    signature = private_key.sign(
        doc_bytes,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode('utf-8')
    
    # Simpan ke database
    document_db[doc_id] = {
        "content": doc_content,
        "hash": sha256_hash,
        "signature": signature_b64
    }
    
    # 3. URL Verifikasi langsung mengarah ke halaman dedicated verify
    verify_url = f"http://localhost:5000/verify/{doc_id}"
    
    # 4. Generate QR Code (Diperbaiki menggunakan warna 'black')
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    qr.add_data(verify_url)
    qr.make(fit=True)
    
    img = qr.make_image(fill_color="black", back_color="white")
    buffered = io.BytesIO()
    img.save(buffered, format="PNG")
    qr_base64 = base64.b64encode(buffered.getvalue()).decode('utf-8')
    
    return render_template('index.html', 
                           qr_code=qr_base64, 
                           doc_id=doc_id, 
                           doc_hash=sha256_hash,
                           signature=signature_b64,
                           success=True)

@app.route('/verify/<doc_id>')
def verify_document(doc_id):
    doc = document_db.get(doc_id)
    if not doc:
        return render_template('verify.html', status="INVALID", doc_id=doc_id, message="Dokumen tidak ditemukan di dalam database sistem.")
        
    try:
        # Proses Verifikasi Kriptografi RSA
        doc_bytes = doc["content"].encode('utf-8')
        decoded_signature = base64.b64decode(doc["signature"])
        
        public_key.verify(
            decoded_signature,
            doc_bytes,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return render_template('verify.html', status="VALID", doc_id=doc_id, content=doc["content"], hash_val=doc["hash"], signature=doc["signature"])
        
    except InvalidSignature:
        return render_template('verify.html', status="TAMPERED", doc_id=doc_id, message="Peringatan! Tanda tangan tidak valid atau dokumen telah dimanipulasi.")

@app.route('/verify-manual', methods=['POST'])
def verify_manual():
    search_id = request.form.get('search_id')
    return redirect(url_for('verify_document', doc_id=search_id))

if __name__ == '__main__':
    app.run(debug=True, port=5000)