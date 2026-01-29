# Secure Media Delivery System (DRM Simulation) 🔒📺

A comprehensive simulation of a DRM (Digital Rights Management) ecosystem implemented in Python using TCP Sockets and Cryptography.

## 🚀 Overview
This project simulates the complete lifecycle of secure content delivery, including:
1.  **Content Server:** Hosting encrypted media. **Note:** The server automatically creates a folder named `/archivos` on its first run; this is where the media content (text, images) to be detected by the application should be placed.
2.  **License Server:** Issuing AES decryption keys securely via RSA encryption.
3.  **CDM (Content Decryption Module):** A secure local proxy that handles decryption.
4.  **User Agent (Client):** The media player interface (`application.py`).

## 💧 Watermarking Feature
The system includes an image processing feature using the `Pillow` library. When a user requests an image, the Content Server applies a visible watermark with the User ID. The processed image is generated as a new file (e.g., `imagen_marca.png`) to demonstrate server-side content modification.

## 🛠️ Architecture & Technologies
* **Language:** Python 3.x
* **Networking:** Raw TCP Sockets (Custom protocol design).
* **Cryptography:** `cryptography.hazmat` (RSA for key exchange, AES-CTR for content).
* **Image Processing:** `PIL` (Pillow) for dynamic watermarking.

## ⚙️ How to Run
1.  **Generate Keys:** Run `python generate_keys_cdm.py` to create the RSA key pair.
2.  **Setup Content:** Run `python content_server.py` once to create the `/archivos` folder, then place your files inside.
3.  **Start Servers:**
    * `python content_server.py` (Port 5000)
    * `python license_server.py` (Port 6000)
    * `python cdm.py` (Port 7000)
4.  **Run Client:**
    * `python application.py`

## 🎓 Context
Developed as part of the *Digital Technology and Multimedia* degree coursework at **Polytechnic University of Valencia (UPV)**.
