import streamlit as st
# Allow up to 1GB upload
#st.set_option('server.maxUploadSize', 1024)
import pandas as pd
from Crypto.Cipher import AES

import binascii

st.title("MySQL-Compatible AES Encrypt/Decrypt CSV")

# Key input
key_input = st.text_input("Enter AES Key (same as used in MySQL)", type="password")

def get_aes_cipher(key_text):
    key = key_text.encode("utf-8")
    key = key.ljust(16, b'\0')  # pad to 16 bytes
    return AES.new(key, AES.MODE_ECB)

def pad(s):
    pad_len = 16 - (len(s) % 16)
    return s + (chr(pad_len) * pad_len).encode()

def unpad(s):
    return s[:-s[-1]]

def encrypt_text(plain_text, cipher):
    if pd.isna(plain_text):
        return plain_text
    data = str(plain_text).encode()
    encrypted = cipher.encrypt(pad(data))
    return binascii.hexlify(encrypted).decode().upper()

def decrypt_text(encrypted_hex, cipher):
    if pd.isna(encrypted_hex):
        return encrypted_hex
    try:
        decrypted = cipher.decrypt(binascii.unhexlify(encrypted_hex))
        return unpad(decrypted).decode()
    except Exception:
        return None  # invalid data or wrong key

# Upload CSV
uploaded_file = st.file_uploader("Upload a CSV file", type=["csv"])

if uploaded_file and key_input:
    df = pd.read_csv(uploaded_file)
    st.write("Original Data:")
    st.dataframe(df)

    columns = df.columns.tolist()

    # MULTISELECT COLUMNS
    selected_columns = st.multiselect("Select columns to encrypt/decrypt", columns)

    action = st.radio("Choose Action", ["Encrypt", "Decrypt"])

    if st.button("Run"):
        if not selected_columns:
            st.warning("Please select at least one column.")
        else:
            cipher = get_aes_cipher(key_input)

            for col in selected_columns:
                if action == "Encrypt":
                    df[col] = df[col].apply(lambda x: encrypt_text(x, cipher))
                else:
                    df[col] = df[col].apply(lambda x: decrypt_text(x, cipher))

            st.success(f"Columns {selected_columns} processed successfully ({action}).")

            st.write("Processed Data:")
            st.dataframe(df)

            # Download Result
            csv = df.to_csv(index=False).encode()
            st.download_button(
                "Download Result CSV",
                data=csv,
                file_name="processed.csv",
                mime="text/csv"
            )
