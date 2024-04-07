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

os.system("ip addr add 192.168.52.1/24 dev {}".format(ifname))
os.system("ip link set dev {} up".format(ifname))

os.system("sysctl -w net.ipv4.ip_forward=1")
os.system("ip route add 192.168.52.1/24 dev {}".format(ifname))

serverIP = "10.9.0.11"
serverPort = 5555

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.bind((serverIP, serverPort))
sock.listen(5)
print("Server listening on {}:{}".format(serverIP, serverPort))

def generate_private_key():
    # Generate a random private key
    return random.randint(2, p - 2)

def diffie_hellman_key_exchange(client_socket):
    # Server's private key
    x_server = generate_private_key()

    # Receive client's public key
    client_public_key = int(client_socket.recv(2048).decode())

    # Calculate server's public key
    y_server = pow(g, x_server, p)

    # Send server's public key to the client
    client_socket.send(str(y_server).encode())

    # Calculate the shared secret
    shared_secret = pow(client_public_key, x_server, p)
    print("Server side shared key:", shared_secret)
    return shared_secret

# AES encryption function with CFB mode
def encrypt_aes(key, plaintext):
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CFB, iv)
    ciphertext = iv + cipher.encrypt(plaintext)
    print("Server side cipher text:", ciphertext)
    return ciphertext

# AES decryption function with CFB mode
def decrypt_aes(key, ciphertext):
    iv = ciphertext[:16]
    cipher = AES.new(key, AES.MODE_CFB, iv)
    plaintext = cipher.decrypt(ciphertext[16:])
    print("Server side plain text:", plaintext)
    return plaintext

client_sockets = []
lock = threading.Lock()

def handle_client(client_socket):
    # Perform Diffie-Hellman key exchange
    shared_secret = diffie_hellman_key_exchange(client_socket)

    # Create AES key from the shared secret
    aes_key = hashlib.sha256(str(shared_secret).encode()).digest()[:16]

    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                print("Connection closed by the client {}".format(client_socket.getpeername()))
                with lock:
                    client_sockets.remove(client_socket)
                client_socket.close()
                break

            # Extract shared key and encrypted packet
            parts = data.split(b'|')
            if len(parts) != 2:
                print("Invalid data format received from client")
                continue
            received_aes_key = parts[0]
            encrypted_packet = parts[1]

            if received_aes_key != aes_key:
                print("Shared key verification failed for client {}".format(client_socket.getpeername()))
                with lock:
                    client_sockets.remove(client_socket)
                client_socket.close()
                break

            decrypted_data = decrypt_aes(aes_key, encrypted_packet)
            pkt = IP(decrypted_data)
            print("Received packet: {} --> {}".format(pkt.src, pkt.dst))
            os.write(tun, bytes(pkt))

            # Read from TUN and send to the client
            data = os.read(tun, 2048)
            encrypted_data = encrypt_aes(aes_key, data)
            data_to_send = aes_key + b'|' + encrypted_data
            client_socket.send(data_to_send)
            # Receive response from client and send it to the tun interface
            #response = client_socket.recv(2048)
            #decrypted_response = decrypt_aes(aes_key, response)
            #response_pkt = IP(decrypted_response)
            #os.write(tun, bytes(response_pkt))
        except Exception as e:
            print("Error handling client:", e)
            client_socket.close()
            break

while True:
    client_sock, client_addr = sock.accept()
    print("Connection established with {}".format(client_addr))
    with lock:
        client_sockets.append(client_sock)

    # Create a new thread for each client
    client_thread = threading.Thread(target=handle_client, args=(client_sock,))
    client_thread.start()

