SwiftSign Digital Signature

Overview

SwiftSign Digital Signature is a secure and user-friendly application designed for generating, signing, and verifying digital signatures, with a focus on licensing applications. Developed as a graduation project for the Department of Cyber Security and Data Analytics at the Faculty of Electronic Engineering, Menoufia University, SwiftSign ensures the authenticity and integrity of digital licenses using advanced cryptographic techniques.

The application supports multiple cryptographic algorithms, including ECC (ECDSA), RSA, ElGamal (RSA-PSS based), and Diffie-Hellman (HMAC-SHA256 based). It features a modern GUI with drag-and-drop functionality, batch processing, and customizable settings to enhance user experience.

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



Certificate Generation: Create self-signed X.509 certificates for enhanced security.



Feedback Mechanism: Submit feedback directly through the application or via GitHub Issues.

Supported Algorithms

SwiftSign implements the following cryptographic algorithms:





ECC (ECDSA): Uses the NIST256p curve with SHA-256 for efficient and secure signatures.



RSA: Employs RSASSA-PSS with 2048-bit keys and SHA-256 for robust signing and verification.



ElGamal: A custom implementation based on RSA-PSS with SHA-256, adapted for digital signatures.



Diffie-Hellman: Uses DH key exchange to derive a shared secret, combined with HMAC-SHA256 for signing and verification.

Requirements

To run SwiftSign Digital Signature, ensure the following prerequisites are met:





Python: Version 3.8 or higher.



Dependencies:





tkinter: For the graphical user interface (included with Python).



cryptography: For RSA, Diffie-Hellman, and certificate operations (pip install cryptography).



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



Verify that the images and icons directories are present in the project root, containing:





images/logo darkimage1.png (light theme logo)



images/logo lightimag2.png (dark theme logo)



icons/icon.ico (application icon) If these files are missing, the application will run but may not display the logo or icon correctly.



Run the application:

python SwiftSign Digital Signature.py

Usage





Launch the Application:





Run SwiftSign Digital Signature.py to start the SwiftSign GUI.



The interface includes tabs for Key Generation, Signing, Verification, Batch Operations, Certificate, Settings, and About.



Key Generation:





Select a save directory and choose an algorithm (ECC, RSA, ElGamal, or Diffie-Hellman).



Generate key pairs, saved as PEM files in the specified directory.



License Signing:





Select a private key and algorithm, then choose data files to sign.



Save the signature files (.sig) in the specified output directory.



License Verification:





Select the public key, data file, and signature file.



Verify the signature to confirm the data's authenticity and integrity.



Batch Operations:





Add multiple data files for batch signing or data-signature pairs for batch verification.



Specify output directories and keys, then execute batch operations.



Certificate Generation:





Provide certificate details (Country, Organization, Common Name).



Generate a self-signed X.509 certificate using the last generated key pair.



Settings:





Configure the default key directory, preferred algorithm, UI animations, and dark mode.



About:





View application details, features, and contact information.

Troubleshooting





Missing Logo or Icon:





Ensure the images and icons directories contain the required files (logo darkimage1.png, logo lightimag2.png, icon.ico).



If files are missing, the application will run but may display warnings in the console.



Drag-and-Drop Not Working:





Verify that tkinterdnd2 is installed (pip install tkinterdnd2).



Without tkinterdnd2, drag-and-drop is disabled, but file selection via browsing is still available.



Key Generation or Signing Errors:





Ensure the selected directory has write permissions.



Verify that the private key is valid and not password-protected (SwiftSign expects unencrypted keys).



Verification Fails:





Confirm that the public key, data file, and signature file correspond to each other.



For Diffie-Hellman, ensure the private key is available for verification, as it uses HMAC-SHA256 with a derived shared secret.



UI Issues:





If the UI does not render correctly, ensure ttkthemes is installed.



Toggle dark mode or animations in Settings to resolve display issues.

Directory Structure





SwiftSign Digital Signature.py: Main application script.



images/: Contains logo files (logo darkimage1.png, logo lightimag2.png).



icons/: Contains the application icon (icon.ico).



README.md: Project documentation (this file).



requirements.txt: List of required Python packages.

Notes





Key Security: Store private keys securely and back them up. Do not share private keys.



Diffie-Hellman Signing: Requires both private and public keys for signing and verification due to HMAC-SHA256 with a derived shared secret.



Settings Persistence: Settings are saved to ~/.swiftsign_settings.conf for consistent preferences across sessions.



Certificate Support: Generates self-signed X.509 certificates, compatible with RSA, ECC, and Diffie-Hellman keys.

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