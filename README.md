SwiftSign Digital Signature
Overview
SwiftSign Digital Signature is a robust and secure application designed for generating, signing, and verifying digital signatures, with a focus on licensing applications. Developed as a graduation project for the Department of Cyber Security and Data Analytics at the Faculty of Electronic Engineering, Menoufia University, SwiftSign provides a user-friendly platform to ensure the authenticity and integrity of digital licenses using advanced cryptographic techniques.
This application supports multiple cryptographic algorithms, including ECC (ECDSA), RSA, ElGamal (RSA-PSS based), and Diffie-Hellman (HMAC-SHA256 based), each tailored for secure key generation, signing, and verification. SwiftSign is built with a modern GUI, featuring drag-and-drop functionality, batch processing, and customizable settings for an enhanced user experience.
Features

Key Pair Generation: Generate public and private key pairs for ECC, RSA, ElGamal, and Diffie-Hellman algorithms.
License Signing: Create digitally signed licenses using user-provided data, supporting JSON-based license files.
Signature Verification: Validate the authenticity and integrity of licenses with corresponding public keys.
Batch Processing: Sign or verify multiple license files simultaneously for efficient workflow.
Search Functionality: Locate key or license files within specified directories.
Drag-and-Drop Support: Seamlessly select files via drag-and-drop (requires tkinterdnd2).
User-Friendly Interface: Navigate through intuitive tabs for key generation, signing, verification, batch operations, and settings.
Undo/Redo Functionality: Revert or reapply actions for flexible operation management.
Customizable Settings: Configure default key directories, preferred algorithms, UI animations, and dark mode.
Feedback Mechanism: Submit feedback directly through the application or via GitHub Issues.

Supported Algorithms
SwiftSign implements the following cryptographic algorithms:

ECC (ECDSA): Utilizes the NIST256p curve with SHA-256 for efficient and secure signatures.
RSA: Employs RSASSA-PSS with 2048-bit keys and SHA-256 for robust signing and verification.
ElGamal: A custom implementation based on RSA-PSS with SHA-256, adapted for digital signatures.
Diffie-Hellman: Uses DH key exchange to derive a shared secret, combined with HMAC-SHA256 for signing and verification.

Requirements
To run SwiftSign Digital Signature, ensure the following prerequisites are met:

Python: Version 3.8 or higher
Dependencies:
tkinter: For the graphical user interface (included with Python).
cryptography: For RSA, Diffie-Hellman, and cryptographic operations (pip install cryptography).
ecdsa: For ECC (ECDSA) operations (pip install ecdsa).
tkinterdnd2 (optional): For drag-and-drop functionality (pip install tkinterdnd2).
Pillow: For logo rendering in the GUI (pip install Pillow).
ttkthemes: For enhanced UI themes (pip install ttkthemes).



Install dependencies using:
pip install cryptography ecdsa tkinterdnd2 Pillow ttkthemes

Installation

Clone the repository:
git clone https://github.com/rayder54321/SwiftSign-Digital-Signature-program.git
cd SwiftSign-Digital-Signature-program


Install the required Python packages:
pip install -r requirements.txt


Ensure the images and icons directories are present in the project root with the required logo and icon files (logo darkimage1.png, logo lightimag2.png, icon.ico).

Run the application:
python digital_signature_app.py



Usage

Launch the Application:

Run digital_signature_app.py to start the SwiftSign GUI.
The interface includes tabs for Key Generation, License Signing, License Verification, Batch Operations, Search, Settings, and About.


Key Generation:

Select a save directory and choose an algorithm (ECC, RSA, ElGamal, or Diffie-Hellman).
Generate key pairs, which are saved as PEM files in the specified directory.


License Signing:

Enter license details (Customer Name, Email, Expiry Date, optional Hardware ID).
Select a private key and algorithm, then save the license data (JSON) and signature files.


License Verification:

Select the public key, license data file, and signature file.
Verify the signature to confirm the license's authenticity and integrity.


Batch Operations:

Add multiple data files for batch signing or data-signature pairs for batch verification.
Specify output directories and keys, then execute batch operations.


Search:

Search for key files in a specified directory using a search term.


Settings:

Configure the default key directory, preferred algorithm, UI animations, and dark mode.


About:

View application details, features, and contact information.



Directory Structure

digital_signature_app.py: Main application script.
images/: Contains logo files (logo darkimage1.png, logo lightimag2.png).
icons/: Contains the application icon (icon.ico).
README.md: Project documentation (this file).

Notes

Key Security: Always store private keys securely and back them up. Do not share private keys.
Diffie-Hellman Signing: The DH implementation uses HMAC-SHA256 with a derived shared secret, requiring both private and public keys for signing and verification.
Drag-and-Drop: Requires the tkinterdnd2 library; without it, drag-and-drop is disabled, but file selection via browsing remains functional.
Settings Persistence: Settings are saved to ~/.swiftsign_settings.json for consistent user preferences across sessions.

Contact & Support
For additional information, support, or to contribute to the project, visit:

GitHub Repository: https://github.com/rayder54321/SwiftSign-Digital-Signature-program
Documentation: Detailed guides and setup instructions are available in the repository's README.
Issue Reporting: Submit bugs or feature requests via GitHub Issues.
Feedback: Use the in-app feedback form or GitHub Issues to provide feedback.

License
This project is licensed under the MIT License. See the LICENSE file for details.
Authors

Mohamed Nassar
Ahmed El Shaboury
Ahmed Maged

Developed as part of the graduation project for the Department of Cyber Security and Data Analytics, Faculty of Electronic Engineering, Menoufia University.
