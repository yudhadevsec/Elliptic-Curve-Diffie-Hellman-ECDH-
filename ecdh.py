"""
ecdh_interactive.py — Pertukaran Shared Secret Key (Interaktif)

Algoritma : ECDH Curve25519 (menggantikan DH klasik)
Autentikasi: Ed25519 digital signature (anti-MITM)
KDF        : HKDF-SHA256 (derive final key)

Esensi yang dibuktikan:
  - Dua pihak (Pihak A & Pihak B) hanya bertukar PUBLIC KEY.
  - Masing-masing menghitung shared secret dari private key sendiri 
    terhadap public key lawan -> hasilnya IDENTIK.
  - Ed25519 signature membuktikan public key tidak dimanipulasi (anti-MITM).

Cara pakai:
  python kripto.py
"""

import hashlib
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey, Ed25519PublicKey
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey
)
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.exceptions import InvalidSignature


# ==============================================
#  HELPER FUNCTIONS
# ==============================================

def pub_to_hex(key) -> str:
    """Mengubah kunci publik ke dalam representasi string hex."""
    return key.public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    ).hex()


def separator(title: str = ""):
    """Mencetak garis pemisah untuk mempercantik tampilan output."""
    if title:
        print(f"\n╔{'═'*60}╗")
        print(f"║  {title:<58}║")
        print(f"╚{'═'*60}╝")
    else:
        print("\n" + "─" * 62)


def pause(msg: str = "Tekan Enter untuk lanjut..."):
    """Memberikan jeda waktu berdasar interaksi pengguna."""
    input(f"\n  [ {msg} ] ")


# ==============================================
#  LANGKAH 1 — PIHAK A: Generate Key Pair
# ==============================================

def pihak_a_generate(nama: str):
    separator(f"LANGKAH 1 — {nama} Generate Key Pair")
    print(f"""  {nama} membuat dua pasang kunci:
    * X25519  -> Untuk pertukaran shared secret (ECDH)
    * Ed25519 -> Untuk menandatangani public key (Anti-MITM)""")

    # 1. Generate Private Keys
    ecdh_priv = X25519PrivateKey.generate()
    sign_priv = Ed25519PrivateKey.generate()

    # 2. Extract Public Keys
    ecdh_pub_bytes = ecdh_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    sign_pub_hex = pub_to_hex(sign_priv.public_key())
    
    # 3. Create Digital Signature
    signature = sign_priv.sign(ecdh_pub_bytes).hex()
    ecdh_pub_hex = ecdh_pub_bytes.hex()

    print(f"\n  ECDH Public Key  : {ecdh_pub_hex}")
    print(f"  Sign Public Key  : {sign_pub_hex}")
    print(f"  Signature        : {signature}")
    print(f"""
  ^ Tiga nilai di atas adalah data Kunci Publik yang akan dikirim.
    (Salin ketiga baris nilai hex di atas nantinya)\n""")
    
    pause()
    return ecdh_priv, ecdh_pub_hex, sign_pub_hex, signature


# ==============================================
#  LANGKAH 2-4 — PIHAK B: Menerima, Verifikasi, Hitung Secret
# ==============================================

def pihak_b_step(nama_b: str, nama_a: str, a_ecdh_pub_hex: str, a_sign_pub_hex: str, a_sig_hex: str):
    separator(f"LANGKAH 2 — {nama_b} Menerima Data & Generate Key Pair")
    print(f"  {nama_b} membuat dua pasang kunci dengan proses yang sama secara lokal.")

    # 1. Generate Private Keys (Pihak B)
    ecdh_priv = X25519PrivateKey.generate()
    sign_priv = Ed25519PrivateKey.generate()

    # 2. Extract Public Keys
    ecdh_pub_bytes = ecdh_priv.public_key().public_bytes(
        serialization.Encoding.Raw,
        serialization.PublicFormat.Raw
    )
    sign_pub_hex = pub_to_hex(sign_priv.public_key())
    
    # 3. Create Digital Signature
    signature = sign_priv.sign(ecdh_pub_bytes).hex()
    ecdh_pub_hex = ecdh_pub_bytes.hex()

    print(f"\n  ECDH Public Key  : {ecdh_pub_hex}")
    print(f"  Sign Public Key  : {sign_pub_hex}")
    print(f"  Signature        : {signature}")
    print(f"""
  ^ Tiga nilai di atas adalah data Kunci Publik milik {nama_b} yang 
    akan dikirim kembali. (Salin ketiga baris nilai hex di atas nantinya)\n""")

    pause("Memproses validasi...")

    separator(f"LANGKAH 3 — {nama_b} Verifikasi Signature {nama_a}")
    print(f"  Memastikan bahwa kunci publik ECDH {nama_a} sah dan tidak dimanipulasi peretas.")

    # Verifikasi Ed25519
    try:
        a_sign_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(a_sign_pub_hex))
        a_sign_key.verify(bytes.fromhex(a_sig_hex), bytes.fromhex(a_ecdh_pub_hex))
        print(f"  [ OK ] Signature {nama_a} TERVERIFIKASI.")
    except InvalidSignature:
        print(f"  [ !! ] Peringatan Keamanan: Signature TIDAK VALID (Terindikasi MITM).")
        return None, None, None, None, None, None
    except Exception as e:
        print(f"  [ !! ] Error saat validasi data: {e}")
        return None, None, None, None, None, None

    separator(f"LANGKAH 4 — {nama_b} Hitung Shared Secret (HKDF)")
    print(f"  Rumus: [Private {nama_b}] x [Public {nama_a}] -> Raw Secret -> HKDF")

    # Hitung ECDH
    a_ecdh_key = X25519PublicKey.from_public_bytes(bytes.fromhex(a_ecdh_pub_hex))
    raw_secret = ecdh_priv.exchange(a_ecdh_key)

    # Derivasi menggunakan HKDF
    salt = bytes(x ^ y for x, y in zip(bytes.fromhex(a_ecdh_pub_hex), ecdh_pub_bytes))
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ecdh-interactive-v1"
    )
    secret_b = hkdf.derive(raw_secret)

    print(f"  Shared Secret {nama_b} : {secret_b.hex()}")
    
    pause()
    return ecdh_priv, ecdh_pub_hex, sign_pub_hex, signature, secret_b, salt


# ==============================================
#  LANGKAH 5-6 — PIHAK A: Verifikasi Balasan & Finalisasi
# ==============================================

def pihak_a_finalize(nama_a: str, nama_b: str, a_ecdh_priv, a_ecdh_pub_hex: str, 
                     b_ecdh_pub_hex: str, b_sign_pub_hex: str, b_sig_hex: str, 
                     secret_b: bytes, salt: bytes):

    separator(f"LANGKAH 5 — {nama_a} Verifikasi Signature {nama_b}")
    print(f"  Memastikan bahwa kunci publik ECDH {nama_b} sah dan tidak diretas di jalan.")

    # Verifikasi Ed25519
    try:
        b_sign_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(b_sign_pub_hex))
        b_sign_key.verify(bytes.fromhex(b_sig_hex), bytes.fromhex(b_ecdh_pub_hex))
        print(f"  [ OK ] Signature {nama_b} TERVERIFIKASI.")
    except InvalidSignature:
        print(f"  [ !! ] Peringatan Keamanan: Signature TIDAK VALID (Terindikasi MITM).")
        return
    except Exception as e:
        print(f"  [ !! ] Error saat validasi data: {e}")
        return

    separator(f"LANGKAH 6 — {nama_a} Hitung Shared Secret (HKDF)")
    print(f"  Rumus: [Private {nama_a}] x [Public {nama_b}] -> Raw Secret -> HKDF")

    # Hitung ECDH
    b_ecdh_key = X25519PublicKey.from_public_bytes(bytes.fromhex(b_ecdh_pub_hex))
    raw_secret = a_ecdh_priv.exchange(b_ecdh_key)

    # Derivasi menggunakan HKDF (dengan salt dan info yang sama persis)
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"ecdh-interactive-v1"
    )
    secret_a = hkdf.derive(raw_secret)

    print(f"  Shared Secret {nama_a} : {secret_a.hex()}")
    
    pause("Mencocokkan Shared Secret antara kedua pihak...")

    # Verifikasi Akhir
    separator("HASIL AKHIR — Validasi Kunci Gabungan")
    if secret_a == secret_b:
        print(f'''
  ╔════════════════════════════════════════════════════════════╗
  ║  [ SUCCESS ] SHARED SECRET MATCH!{' ':>26}║
  ║                                                            ║
  ║  Kedua pihak secara independen berhasil mencetak KUNCI     ║
  ║  YANG SAMA PERSIS lewat pertukaran kunci publik. Ini       ║
  ║  membuktikan keajaiban matematika Kurva Eliptik (ECDH).    ║
  ╚════════════════════════════════════════════════════════════╝''')
        print(f"\n  Final Secret Key : {secret_a.hex()}")
        print(f"  Kekuatan Kunci   : {len(secret_a) * 8}-bit Asymmetric Security")
        print(f"  Fingerprint      : {hashlib.sha256(secret_a).hexdigest()[:32]}...")
    else:
        print("  [ FAILED ] ERROR Kritis: Shared Secret tidak cocok!")

    print("\n  >>> Simulasi Pertukaran Kunci Selesai. <<<\n")


# ==============================================
#  FUNGSI UTAMA (MAIN PROGRAM)
# ==============================================

def main():
    print("""
╔════════════════════════════════════════════════════════════╗
║   Simulasi Pertukaran Kunci Aman (X25519 + Ed25519)        ║
║   Konsep Matematika Kriptografi Kuat Anti-Penyadapan       ║
╚════════════════════════════════════════════════════════════╝
    """)

    # Nama entitas simulasi
    separator("PENGATURAN AWAL")
    print("  Masukkan nama untuk masing-masing pihak.")
    print("  Contoh: 'Alice' & 'Bob', 'Server' & 'Client'\\n")
    
    nama_a = input("  Nama Pihak Pertama : ").strip() or "Alice"
    nama_b = input("  Nama Pihak Kedua   : ").strip() or "Bob"
    
    print(f"\\n  Memulai transfer kunci antara {nama_a} dan {nama_b}.\\n")
    pause("Tekan Enter untuk mulai...")

    # --- Eksekusi Flow A to B ---
    
    # 1. Pihak A Generate Keys
    a_ecdh_priv, a_ecdh_pub, a_sign_pub, a_sig = pihak_a_generate(nama_a)

    # 2. Transmisi Data Publik dari A -> B (Simulasi)
    separator(f"INPUT — Data dari {nama_a} dikirim ke {nama_b}")
    print(f"  (Salin/Copy output {nama_a} di atas dan paste/tempel di sini)\\n")
    
    a_ecdh_in = input(f"  {nama_a} ECDH Public Key : ").strip()
    a_sign_in = input(f"  {nama_a} Sign Public Key : ").strip()
    a_sig_in  = input(f"  {nama_a} Signature       : ").strip()

    # 3. Pihak B Proses Data dari A, Generate lokal, & Hitung Secret
    result = pihak_b_step(nama_b, nama_a, a_ecdh_in, a_sign_in, a_sig_in)
    if result[0] is None:
        return # Terputus bila verifikasi MITM gagal
    _, b_ecdh_pub, b_sign_pub, b_sig, secret_b, salt = result

    # 4. Transmisi Data Publik Balasan dari B -> A (Simulasi)
    separator(f"INPUT — Data Balasan {nama_b} kepada {nama_a}")
    print(f"  (Salin/Copy output {nama_b} di atas dan paste/tempel di sini)\\n")
    
    b_ecdh_in = input(f"  {nama_b} ECDH Public Key : ").strip()
    b_sign_in = input(f"  {nama_b} Sign Public Key : ").strip()
    b_sig_in  = input(f"  {nama_b} Signature       : ").strip()

    # 5. Pihak A Verifikasi balasan dan mencocokkan Secret Key
    pihak_a_finalize(
        nama_a, nama_b,
        a_ecdh_priv, a_ecdh_pub,
        b_ecdh_in, b_sign_in, b_sig_in,
        secret_b, salt
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\n\\n[*] Program dihentikan oleh pengguna.")
