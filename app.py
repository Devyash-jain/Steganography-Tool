import tkinter as tk
from tkinter import filedialog, messagebox
from PIL import Image, ImageTk
from Cryptodome.Cipher import AES
import base64

# Define colors and styles
BG_COLOR = "#0A192F"  # Dark navy blue
FG_COLOR = "#64FFDA"  # Neon cyan
BUTTON_BG = "#112240"  # Slightly lighter navy
BUTTON_FG = "#64FFDA"
FONT_TITLE = ("Arial", 20, "bold")
FONT_TEXT = ("Arial", 12)

# AES Encryption Key (Must be 16, 24, or 32 bytes long)
AES_KEY = b'16byteSecretKey!'


# Function to pad text for AES
def pad(text):
    return text + (16 - len(text) % 16) * " "


# Encrypt text using AES
def encrypt_text(text):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(pad(text).encode())).decode()


# Decrypt text using AES
def decrypt_text(encrypted_text):
    cipher = AES.new(AES_KEY, AES.MODE_ECB)
    return cipher.decrypt(base64.b64decode(encrypted_text)).decode().strip()


# Convert text to binary
def text_to_binary(text):
    return ''.join(format(ord(char), '08b') for char in text)


# Convert binary to text
def binary_to_text(binary_str):
    return ''.join(chr(int(binary_str[i:i + 8], 2)) for i in range(0, len(binary_str), 8))


# Hide text in image
def hide_text(image_path, secret_text, output_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    encrypted_text = encrypt_text(secret_text)
    binary_text = text_to_binary(encrypted_text) + '1111111111111110'  # Delimiter

    binary_index = 0
    new_pixels = []

    for pixel in pixels:
        if binary_index < len(binary_text):
            new_pixel = list(pixel)
            for i in range(3):  # Modify R, G, B values
                if binary_index < len(binary_text):
                    new_pixel[i] = (new_pixel[i] & 0xFE) | int(binary_text[binary_index])
                    binary_index += 1
            new_pixels.append(tuple(new_pixel))
        else:
            new_pixels.append(pixel)

    img.putdata(new_pixels)
    img.save(output_path)
    messagebox.showinfo("Success", f"Message hidden successfully in {output_path}")


# Extract text from image
def extract_text(image_path):
    img = Image.open(image_path)
    pixels = list(img.getdata())

    binary_text = ""
    for pixel in pixels:
        for i in range(3):  # Extract from R, G, B
            binary_text += str(pixel[i] & 1)

    delimiter = "1111111111111110"
    if delimiter in binary_text:
        binary_text = binary_text[:binary_text.index(delimiter)]

    decrypted_text = decrypt_text(binary_to_text(binary_text))
    messagebox.showinfo("Hidden Message", f"Extracted Message: {decrypted_text}")


# GUI
class SteganoApp:

    def __init__(self, root):
        self.root = root
        self.root.title("Steganography Tool")
        self.root.geometry("600x400")
        self.root.config(bg=BG_COLOR)

        # Title
        self.title_label = tk.Label(root, text="Steganography Tool", font=FONT_TITLE, fg=FG_COLOR, bg=BG_COLOR)
        self.title_label.pack(pady=20)

        # Container Frame for Centering
        self.frame = tk.Frame(root, bg=BG_COLOR)
        self.frame.pack(pady=10)

        # Select Image Button
        self.select_button = tk.Button(self.frame, text="Select Image", font=FONT_TEXT, bg=BUTTON_BG, fg=BUTTON_FG,
                                       width=20, height=2, relief="flat", command=self.select_image, bd=0,
                                       highlightthickness=0)
        self.select_button.pack(pady=10)

        # Secret Message Entry
        self.message_entry = tk.Entry(self.frame, font=FONT_TEXT, width=40, bg=BUTTON_BG, fg=FG_COLOR,
                                      insertbackground=FG_COLOR, relief="flat", bd=5, highlightbackground=FG_COLOR,
                                      highlightcolor=FG_COLOR)
        self.message_entry.pack(pady=10)
        self.message_entry.insert(0, "Enter secret message...")

        # Encode & Decode Buttons
        self.encode_button = tk.Button(self.frame, text="Hide Message", font=FONT_TEXT, bg=BUTTON_BG, fg=BUTTON_FG,
                                       width=20, height=2, relief="flat", command=self.encode_message, bd=0,
                                       highlightthickness=0)
        self.encode_button.pack(pady=10)

        self.decode_button = tk.Button(self.frame, text="Extract Message", font=FONT_TEXT, bg=BUTTON_BG, fg=BUTTON_FG,
                                       width=20, height=2, relief="flat", command=self.decode_message, bd=0,
                                       highlightthickness=0)
        self.decode_button.pack(pady=10)

        self.image_path = ""

    def select_image(self):
        self.image_path = filedialog.askopenfilename(filetypes=[("Image Files", "*.png;*.bmp")])
        if self.image_path:
            messagebox.showinfo("Selected Image", f"Selected: {self.image_path}")

    def encode_message(self):
        # messagebox.showinfo("Info", "Encoding functionality will be added here.")
        if not self.image_path:
            messagebox.showwarning("Warning", "Please select an image first!")
            return
        message = self.message_entry.get()
        if not message:
            messagebox.showwarning("Warning", "Please enter a message to hide!")
            return
        output_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG Image", "*.png")])
        if output_path:
            hide_text(self.image_path, message, output_path)

    def decode_message(self):
        # messagebox.showinfo("Info", "Decoding functionality will be added here.")
        if not self.image_path:
            messagebox.showwarning("Warning", "Please select an image first!")
            return
        extract_text(self.image_path)

# Run the application
if __name__ == "__main__":
    root = tk.Tk()
    app = SteganoApp(root)
    root.mainloop()


