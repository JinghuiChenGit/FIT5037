#!/usr/bin/env python3
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.serialization import *
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as pad
import binascii as ba
import os
import socketserver
import sys
import hashlib

def load_dh_params():
    with open('./dh_2048_params.bin', 'rb') as f:
         params = load_pem_parameters(f.read(), default_backend())
    print('Parameters have been read from file, Server is ready for requests ...')
    return params

def read_file(filename):
    with open('./data/'+filename, 'rb') as f:
         content = f.read()
    return content

def generate_dh_prvkey(params):
    return params.generate_private_key()

def check_client_pubkey(pubkey):
    if isinstance(pubkey, dh.DHPublicKey):
        return True
    else:
        return False

class Dh_Handler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
      self.params = load_dh_params()
      self.state = 0
      socketserver.BaseRequestHandler.__init__(self, request, client_address, server)

    def handle(self):
      self.data = self.request.recv(3072).strip()
      if self.state == 0 and self.data == b'Connecting':
          self.state = 1

          #Request password, password is encrypted
          private_key = rsa.generate_private_key(public_exponent=65537,key_size=2048,backend=default_backend())
          publickey = private_key.public_key()
          pk = publickey.public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
          self.request.sendall(pk)
          self.data = self.request.recv(3072).strip()
          password = private_key.decrypt(self.data,pad.OAEP(mgf=pad.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None)) 
          #This is the password

          print(password)
          if password == b'root':
              print('Client connected')
              response = b'Server connected!'
              self.request.sendall(response)
          else:
             response = b'wrong password'
             self.request.sendall(response)
             print('Wrong password')
             return
      else:
          response = b'Not understand, hanging up'
          self.request.sendall(response)
          return

      self.data = self.request.recv(3072).strip()
      if self.state == 1 and self.data == b'Params?':
          self.state = 2
          dh_params = self.params
          response = dh_params.parameter_bytes(Encoding.PEM, ParameterFormat.PKCS3)
          self.request.sendall(response)
          print('Parameters sent')
      else:
          response = b'I do not understand you, hanging up'
          self.request.sendall(response)
          return

      self.data = self.request.recv(3072).strip()
      if self.state == 2 and bytearray(self.data)[0:18] == b'Client public key:':
          client_pubkey = load_pem_public_key(bytes(bytearray(self.data)[18:]), default_backend())
          if client_pubkey:
              server_keypair = generate_dh_prvkey(self.params)
              response = b'Server public key:' + server_keypair.public_key().public_bytes(Encoding.PEM, PublicFormat.SubjectPublicKeyInfo)
              shared_secret = server_keypair.exchange(client_pubkey)
              derived_key = HKDF(algorithm = hashes.SHA256(),length=32,salt=None,info=b'handshake data',backend=default_backend()).derive(shared_secret)
              self.state = 3
              print('Recerved client public key')
              self.request.sendall(response)
      else:
          response = b'Invalid client public key, hanging up'
          self.request.sendall(response)
          return

      self.data = self.request.recv(3072).strip()
      if self.state == 3 and self.data == b'File?':
           self.state = 0
           bsecret = ba.hexlify(shared_secret)
           iv = hashlib.md5(bsecret).digest()
           #Encryption
           cipher = Cipher(algorithms.AES(derived_key), modes.CBC(iv), backend=default_backend())
           encryptor = cipher.encryptor()
           filelist = '\n'.join(os.listdir('./data/'))
           print('\n-------Filelist-------')
           print(filelist)
           print('----------------------\n')
           self.request.sendall(filelist.encode())
           filename = self.request.recv(3072).strip()
           pt = read_file(filename.decode("utf-8"))
           print("Plaintext:\n")
           print(pt.decode("utf-8"))

           #Padding,ensure length of file
           padder = padding.PKCS7(128).padder()
           padded_data = padder.update(pt)
           padded_data += padder.finalize()
           print(padded_data)
           ct = encryptor.update(padded_data)
           encryptor.finalize()
           self.request.sendall(ct)
           print(filename.decode("utf-8"),'sent')
           print('\n-----------------------------------')
           print('FIT5057 File Transfer System')
           print('-----------------------------------')
           print('waiting for other connection','\n')
           return

def main():
    print('\n-----------------------------------')
    print('FIT5057 File Transfer System Server')
    print('-----------------------------------')
    print('\nServer waiting for conection')
    host, port = '', 7777
    dh_server = socketserver.TCPServer((host, port), Dh_Handler)
    try:
       dh_server.serve_forever()

    except KeyboardInterrupt:
         dh_server.shutdown()
         sys.exit(0)

if __name__ == '__main__':
    main()
