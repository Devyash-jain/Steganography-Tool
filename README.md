Steganography Tool

Overview:
  This project is a minimalist steganography tool with a cybersecurity-themed UI built using Python and Tkinter. The tool allows users to securely hide and extract messages from image files using LSB (Least Significant Bit) steganography and AES encryption.

Features:
  Minimalist UI with a dark, cybersecurity-inspired theme.
  Image Selection for embedding messages.
  AES Encryption for message security.
  Steganography Encoding & Decoding for message hiding.
  Rounded buttons and structured layout for a better user experience.

Installation:
  Prerequisites:
  Ensure you have Python 3.x installed along with the required dependencies.

Install Required Modules
  pip install pillow pycryptodome

Usage
  Run the application
  python steganography_tool.py
  Select an image (PNG/BMP format recommended).
  Enter a secret message to encode.
  Click 'Hide Message' to embed the message securely.
  To extract the message, click 'Extract Message'.


Future Enhancements:
  Support for more image formats (JPEG, GIF, etc.).
  Advanced encryption options (AES-256, RSA, etc.).
  Drag & Drop functionality for selecting images.
