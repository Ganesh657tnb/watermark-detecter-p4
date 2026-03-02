import os
import sqlite3
import tempfile
import subprocess
import numpy as np
import wave
import streamlit as st
import hmac
import hashlib

# ---------------- CONFIG ----------------
DB_NAME = "guardian.db"
HMAC_KEY = b"guardian_secret_key"
SYNC_BIT = 1
CORRELATION_THRESHOLD = 0.15   # tune if needed

# ---------------- DSSS HELPERS ----------------
def generate_pn_sequence(n):
    np.random.seed(42)
    return (np.random.randint(0, 2, n) * 2 - 1).astype(np.float64)

def derive_watermark_bits(user_id: int):
    digest = hmac.new(
        HMAC_KEY,
        str(user_id).encode(),
        hashlib.sha256
    ).digest()

    truncated = digest[:16]  # 128 bits
    bits = []
    for byte in truncated:
        bits.extend([int(b) for b in format(byte, '08b')])
    return bits

# ---------------- WATERMARK EXTRACTION ----------------
def extract_bits_from_audio(wav_path, bit_count):
    with wave.open(wav_path, 'rb') as wav:
        frames = wav.readframes(wav.getparams().nframes)
        samples = np.frombuffer(frames, dtype=np.int16).astype(np.float64)

    total_samples = len(samples)
    sf = total_samples // bit_count
    pn = generate_pn_sequence(total_samples)

    extracted_bits = []

    for i in range(bit_count):
        segment = samples[i*sf:(i+1)*sf]
        pn_seg = pn[i*sf:(i+1)*sf]

        corr = np.sum(segment * pn_seg)
        extracted_bits.append(1 if corr > 0 else 0)

    return extracted_bits

def similarity(a, b):
    matches = sum(x == y for x, y in zip(a, b))
    return matches / len(a)

# ---------------- STREAMLIT UI ----------------
def main():
    st.set_page_config("Forensic Watermark Detector", layout="centered")
    st.title("🔍 Audio Watermark Forensic Detector")

    st.info("Upload a suspected leaked video to identify the source user.")

    uploaded = st.file_uploader("Upload leaked video", type=["mp4", "mkv", "mov"])

    if uploaded and st.button("Analyze"):
        with st.spinner("Extracting audio & analyzing watermark..."):
            with tempfile.TemporaryDirectory() as tmp:
                video_path = os.path.join(tmp, "leak.mp4")
                audio_path = os.path.join(tmp, "audio.wav")

                with open(video_path, "wb") as f:
                    f.write(uploaded.read())

                subprocess.run([
                    "ffmpeg", "-y",
                    "-i", video_path,
                    "-vn", "-acodec", "pcm_s16le",
                    audio_path
                ], check=True, capture_output=True)

                expected_bits = 1 + 128
                extracted = extract_bits_from_audio(audio_path, expected_bits)

                # Verify sync bit
                if extracted[0] != SYNC_BIT:
                    st.error("❌ No valid watermark detected.")
                    return

                extracted_payload = extracted[1:]

                # Compare against all users
                conn = sqlite3.connect(DB_NAME)
                users = conn.execute("SELECT id FROM users").fetchall()
                conn.close()

                best_match = None
                best_score = 0

                for (uid,) in users:
                    reference = derive_watermark_bits(uid)
                    score = similarity(extracted_payload, reference)

                    if score > best_score:
                        best_score = score
                        best_match = uid

                if best_score >= CORRELATION_THRESHOLD:
                    st.success("✅ Watermark detected!")
                    st.metric("Identified User ID", best_match)
                    st.metric("Confidence Score", f"{best_score:.2f}")
                else:
                    st.warning("⚠️ Watermark weak or not matching any user.")

if __name__ == "__main__":
    main()