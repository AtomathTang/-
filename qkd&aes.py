import random
import time
from tkinter import filedialog, Tk, Button, Label, Entry, StringVar, messagebox
from PIL import Image, ImageTk
import numpy as np
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
import os
import pyperclip


# BB84 协议实现
def create_random_bits(length):
    return [random.randint(0, 1) for _ in range(length)]


def create_random_bases(length):
    return [random.choice(['+', 'x']) for _ in range(length)]


def encode_with_bases(bits, bases):
    return [(bit, base) for bit, base in zip(bits, bases)]


def measure_encoded_bits(encoded_bits, bases):
    measured = []
    for (bit, encode_base), measure_base in zip(encoded_bits, bases):
        if encode_base == measure_base:
            measured.append(bit)
        else:
            measured.append(random.randint(0, 1))  # 不匹配基时结果随机
    return measured


def filter_bits(alice_bases, bob_bases, bits):
    return [bit for a_base, b_base, bit in zip(alice_bases, bob_bases, bits) if a_base == b_base]


def validate_keys(alice_key, bob_key, sample_size):
    sample_indices = random.sample(range(len(alice_key)), sample_size)
    alice_sample = [alice_key[i] for i in sample_indices]
    bob_sample = [bob_key[i] for i in sample_indices]
    return alice_sample == bob_sample


# AES 加密解密函数
def perform_aes_encryption(key, data):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()
    return iv + ciphertext


def perform_aes_decryption(key, ciphertext):
    iv = ciphertext[:16]
    actual_ciphertext = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_plaintext = decryptor.update(actual_ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
    return plaintext


def load_image_data(image_path):
    image = Image.open(image_path)
    return np.array(image)


def save_image_data(image_data, save_path):
    image = Image.fromarray(image_data)
    image.save(save_path)


def convert_image_to_bytes(image_data):
    return image_data.tobytes()


def convert_bytes_to_image(byte_data, shape):
    return np.frombuffer(byte_data, dtype=np.uint8).reshape(shape)


# 仿真参数
key_length = 128

# BB84 协议
alice_initial_bits = create_random_bits(key_length)
alice_initial_bases = create_random_bases(key_length)
encoded_data = encode_with_bases(alice_initial_bits, alice_initial_bases)
bob_initial_bases = create_random_bases(key_length)
measured_data = measure_encoded_bits(encoded_data, bob_initial_bases)
alice_filtered_bits = filter_bits(alice_initial_bases, bob_initial_bases, alice_initial_bits)
bob_filtered_bits = filter_bits(alice_initial_bases, bob_initial_bases, measured_data)
validation_sample_size = key_length // 4
key_validation_result = validate_keys(alice_filtered_bits, bob_filtered_bits, validation_sample_size)

if key_validation_result:
    final_shared_key = alice_filtered_bits[validation_sample_size:]
    aes_encryption_key = bytes(final_shared_key[:16])
else:
    raise Exception("密钥验证失败，可能存在窃听。")

# 创建 Tkinter 窗口
app_window = Tk()
app_window.title("图像加密与解密")
app_window.geometry("600x400")


def copy_key_to_clipboard():
    pyperclip.copy(aes_encryption_key.hex())
    messagebox.showinfo("复制成功", "密钥已复制到剪贴板。")


def encrypt_selected_image():
    image_file_path = filedialog.askopenfilename()
    image_array = load_image_data(image_file_path)
    image_shape = image_array.shape
    image_byte_data = convert_image_to_bytes(image_array)

    start_time = time.time()
    encrypted_byte_data = perform_aes_encryption(aes_encryption_key, image_byte_data)
    encryption_duration = time.time() - start_time

    # 保存加密数据和图像形状
    with open('encrypted_image.bin', 'wb') as f:
        f.write(image_shape[0].to_bytes(4, 'big'))
        f.write(image_shape[1].to_bytes(4, 'big'))
        f.write(image_shape[2].to_bytes(4, 'big'))
        f.write(len(image_byte_data).to_bytes(4, 'big'))  # 保存原始数据长度
        f.write(encrypted_byte_data)

    key_display_label.config(text=f"AES 密钥：{aes_encryption_key.hex()}")
    status_label.config(text=f"图片加密成功，用时：{encryption_duration:.4f} 秒。\n加密图片已保存为 'encrypted_image.bin'。")


def decrypt_selected_image():
    encrypted_file_path = filedialog.askopenfilename()
    user_provided_key = key_input_entry.get()
    aes_decryption_key = bytes.fromhex(user_provided_key)  # 将用户输入的密钥转换为字节

    with open(encrypted_file_path, 'rb') as f:
        shape_0 = int.from_bytes(f.read(4), 'big')
        shape_1 = int.from_bytes(f.read(4), 'big')
        shape_2 = int.from_bytes(f.read(4), 'big')
        original_data_length = int.from_bytes(f.read(4), 'big')  # 读取原始数据长度
        encrypted_byte_data = f.read()

    start_time = time.time()
    decrypted_byte_data = perform_aes_decryption(aes_decryption_key, encrypted_byte_data)
    decryption_duration = time.time() - start_time

    image_shape = (shape_0, shape_1, shape_2)
    decrypted_byte_data = decrypted_byte_data[:original_data_length]  # 截断到原始长度
    decrypted_image_array = convert_bytes_to_image(decrypted_byte_data, image_shape)
    save_image_data(decrypted_image_array, 'decrypted_image.png')

    status_label.config(text=f"图片解密成功，用时：{decryption_duration:.4f} 秒。\n解密图片已保存为 'decrypted_image.png'。")


# 创建 UI 元素
encrypt_button = Button(app_window, text="加密图片", command=encrypt_selected_image)
decrypt_button = Button(app_window, text="解密图片", command=decrypt_selected_image)


key_display_label = Label(app_window, text="")
copy_key_button = Button(app_window, text="复制密钥", command=copy_key_to_clipboard)
status_label = Label(app_window, text="")
key_input_label = Label(app_window, text="输入 AES 密钥（十六进制）：")
key_input_entry = Entry(app_window, width=50)

# 布局 UI 元素
encrypt_button.pack(pady=10)
key_display_label.pack(pady=10)
copy_key_button.pack(pady=10)
key_input_label.pack(pady=10)
key_input_entry.pack(pady=10)
decrypt_button.pack(pady=10)
status_label.pack(pady=10)

# 运行 Tkinter 主循环
app_window.mainloop()
