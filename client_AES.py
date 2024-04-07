#!/usr/bin/python3
import fcntl
import struct
import os
import socket
import select
import threading
import random
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from scapy.all import *

TUNSETIFF = 0x400454ca
IFF_TUN = 0x0001
IFF_NO_PI = 0x1000

# Diffie-Hellman parameters
p = 6668014432879854274079851790721257797144758322315908160396257811764037237817632071521432200871554290742929910593433240445888801654119365080363356052330830046095157579514014558463078285911814024728965016135886601981690748037476461291162945139
g = 2

# Create the tun interface
tun = os.open("/dev/net/tun", os.O_RDWR)
ifr = struct.pack('16sH', b'tun%d', IFF_TUN | IFF_NO_PI)
ifname_bytes = fcntl.ioctl(tun, TUNSETIFF, ifr)

# Get the interface name
ifname = ifname_bytes.decode('UTF-8')[:16].strip("\x00")
print("Interface Name: {}".format(ifname))


os.system("sudo ip addr add 192.168.52.99/24 dev {}".format(ifname))
os.system("sudo ip link set dev {} up".format(ifname))

serverIP = "10.9.0.11"
serverPort = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect((serverIP, serverPort))
print("Connected to server {}:{}".format(serverIP, serverPort))


def generate_private_key():
    # Generate a random private key
    return random.randint(2, p - 2)

def diffie_hellman_key_exchange():
    # Generate client's private key
    x_client = generate_private_key()

    # Send client's public key to the server
    sock.send(str(pow(g, x_client, p)).encode())

    # Receive server's public key
    server_public_key = int(sock.recv(2048).decode())

    # Calculate shared secret
    shared_secret = pow(server_public_key, x_client, p)
    print("Client side shared key:", shared_secret)
    return shared_secret

# AES encryption function with CFB mode
def encrypt_aes(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    print("Client side cipher text:", ciphertext)
    return ciphertext

# AES decryption function with CFB mode
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    print("Client side plaintext:", plaintext)
    return plaintext

def tun_and_server_communication():
    # Perform Diffie-Hellman key exchange
    shared_secret = diffie_hellman_key_exchange()

    # Create AES key from the shared secret
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]

    while True:
        ready, _, _ = select.select([sock, tun], [], [])
        for fd in ready:
            if fd is tun:
                # Reading from TUN and sending to server
                packet = os.read(tun, 2048)
                encrypted_packet = encrypt_aes(aes_key, packet)
                data_to_send = aes_key + b'|' + encrypted_packet
                # Send to the server
                try:
                    sock.send(data_to_send)
                except Exception as e:
                    print("Error sending data to server:", e)
                    return

            elif fd is sock:
                # Reading from server and writing to TUN
                try:
                    data = sock.recv(2048)
                except Exception as e:
                    print("Error receiving data from server:", e)
                    return

                parts = data.split(b'|')

                # Check if the received data is properly formatted
                if len(parts) != 2:
                    print("Invalid data format received from server")
                    continue

                received_aes_key = parts[0]
                encrypted_packet = parts[1]

                if received_aes_key != aes_key:
                    print("Shared key verification failed for server")
                    return

                decrypted_data = decrypt_aes(aes_key, encrypted_packet)
                pkt = IP(decrypted_data)
                print("Received packet: {} --> {}".format(pkt.src, pkt.dst))
                os.write(tun, bytes(pkt))

# Create thread for handling TUN and server communication
tun_and_server_thread = threading.Thread(target=tun_and_server_communication, daemon=True)

# Start the thread
tun_and_server_thread.start()

# The main program will continue without waiting for the thread to finish
while True:
    pass


