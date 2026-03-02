import os
import streamlit as st
import tempfile
import subprocess
import numpy as np
import wave
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

# ---------------- CONFIG ----------------
ALLOWED_EXTENSIONS = {'mp4', 'avi', 'mov', 'webm', 'mkv'}

AES_KEY = b"this_is_16_bytes"   # MUST match embedder
AES_IV  = b"this_is_16_bytes"
PN_SEED = 42
AES_BITS = 128                 # AES-128 payload
# ---------------------------------------

# ---------- FFMPEG ----------

def extract_audio_ffmpeg(video_path, output_wav_path):
    subprocess.run([
        "ffmpeg", "-y", "-i", video_path,
        "-vn", "-acodec", "pcm_s16le",
        output_wav_path
    ], check=True)

# ---------- DSSS ----------

def generate_pn_sequence(length):
    np.random.seed(PN_SEED)
    return (np.random.randint(0, 2, length) * 2 - 1).astype(np.float64)

def bits_to_bytes(bits):
    data = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        data.append(byte)
    return bytes(data)

# ---------- DSSS EXTRACTION ----------

@st.cache_data
def extract_watermark_dsss(input_wav):
    with wave.open(input_wav, "rb") as wav:
        samples = np.frombuffer(
            wav.readframes(wav.getnframes()),
            dtype=np.int16
        ).astype(np.float64)

    total_samples = len(samples)
    payload_bits = AES_BITS
    spreading_factor = total_samples // payload_bits

    if spreading_factor < 100:
        return None, "Audio too short for DSSS extraction"

    pn = generate_pn_sequence(total_samples)
    extracted_bits = []

    for i in range(payload_bits):
        start = i * spreading_factor
        end = start + spreading_factor
        corr = np.mean(samples[start:end] * pn[start:end])
        extracted_bits.append(1 if corr > 0 else 0)

    return extracted_bits, None

# ---------- AES DECRYPT ----------

def aes_decrypt(cipher_bytes):
    cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
    plaintext = unpad(cipher.decrypt(cipher_bytes), 16)
    return plaintext.decode()

# ---------- STREAMLIT APP ----------

def main():
    st.set_page_config(page_title="AES DSSS Watermark Detector", layout="wide")
    st.title("🛡️ AES-128 DSSS Watermark Detector")

    uploaded = st.file_uploader(
        "Upload Watermarked Video",
        type=list(ALLOWED_EXTENSIONS)
    )

    if uploaded and st.button("Detect Watermark"):
        with tempfile.TemporaryDirectory() as tmp:
            video_path = os.path.join(tmp, uploaded.name)
            with open(video_path, "wb") as f:
                f.write(uploaded.read())

            wav_path = os.path.join(tmp, "audio.wav")

            try:
                extract_audio_ffmpeg(video_path, wav_path)
            except Exception:
                st.error("FFmpeg extraction failed")
                return

            with st.spinner("Extracting DSSS watermark..."):
                bits, error = extract_watermark_dsss(wav_path)

            if error:
                st.error(error)
                return

            try:
                cipher_bytes = bits_to_bytes(bits)
                user_id = aes_decrypt(cipher_bytes)

                st.success("✅ Watermark detected successfully")
                st.markdown(f"### 🔓 Extracted User ID: `{user_id}`")

            except Exception:
                st.error("AES decryption failed — corrupted watermark")

if __name__ == "__main__":
    main()
