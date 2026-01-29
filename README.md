# Secure-Socket-Content-System
A Python implementation of a Content Decryption Module (CDM) using TCP Sockets and RSA/AES cryptography
# Secure Media Delivery System (DRM Simulation) 🔒📺

A comprehensive simulation of a DRM (Digital Rights Management) ecosystem implemented in Python using TCP Sockets and Cryptography.

## 🚀 Overview
This project simulates the complete lifecycle of secure content delivery, including:
1.  **Content Server:** Hosting encrypted media and applying dynamic watermarks to images using `Pillow`.
2.  **License Server:** Issuing AES decryption keys securely via RSA encryption.
3.  **CDM (Content Decryption Module):** A secure local proxy that handles decryption without exposing keys to the application layer.
4.  **User Agent (Client):** The media player interface.

## 🛠️ Architecture & Technologies
* **Language:** Python 3.x
* **Networking:** Raw TCP Sockets (Custom protocol design).
* **Cryptography:** `cryptography.hazmat` (RSA for key exchange, AES-CTR for content).
* **Image Processing:** `PIL` (Pillow) for visible watermarking.
* **Protocol:** Custom Handshake (Manifest exchange -> Key Request -> License Acquisition -> Decryption).

## ⚙️ How to Run
1.  **Generate Keys:** Run `python generate_keys_cdm.py` to create the RSA key pair.
2.  **Start Servers:**
    * `python content_server.py` (Port 5000)
    * `python license_server.py` (Port 6000)
    * `python cdm.py` (Port 7000)
3.  **Run Client:**
    * `python application.py`

## 🎓 Context
Developed as part of the *Digital Technology and Multimedia* degree coursework at **Polytechnic University of Valencia (UPV)**.
