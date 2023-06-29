'''client with noise.liqun@outlook.com 20230512'''
import socket
import binascii
from dissononce.cipher.chachapoly import ChaChaPolyCipher
#from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
#from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.IK import IKHandshakePattern
from dissononce.dh.public import PublicKey
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
HOST = '127.0.0.1'    # The remote host
PORT = 50007              # The same port as used by the server
ALGO = ChaChaPolyCipher() # AESGCMCipher()
def main():
    'main'
    # prepare server public key.
    pubkey_bytes = binascii.a2b_hex('e53bb70c354b60d62a0bace9f897b76dcf11f4151feab245ed903175c57a3f12')
    server_pubkey = PublicKey(len(pubkey_bytes), pubkey_bytes)
    client_key = X25519DH().generate_keypair()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        #shake hand.
        ciper = ALGO
        our_handshakestate = HandshakeState(SymmetricState(
                                                    CipherState( ciper ),
                                                    Blake2sHash(), # SHA256Hash
                                                ),
                                            X25519DH(),)
        prologue = b'RandomData'
        our_handshakestate.initialize(IKHandshakePattern(), True, prologue, s=client_key, rs=server_pubkey)
        message_buffer = bytearray()
        our_handshakestate.write_message(b"AuthDataSignedBySecKey", message_buffer)
        print("Send:", len(message_buffer), message_buffer)
        s.sendall(message_buffer)
        message_buffer = bytearray()
        ciphertext = s.recv(4096)
        cipherstates = our_handshakestate.read_message(ciphertext, message_buffer)
        print("Recv:", len(ciphertext), binascii.b2a_hex(ciphertext), ciphertext, message_buffer)
        if message_buffer != b'AuthData2SignedBySecKey':
            print('Auth fail.')
            return
        cipher_state = cipherstates[0]
        decrypt_cipher_state = cipherstates[1]

        #send data.
        data = b'Hello, world'
        ciphertext = cipher_state.encrypt_with_ad(b"", data)
        print("Send:", len(ciphertext), binascii.b2a_hex(ciphertext))
        s.sendall(ciphertext)
        #recv data.
        data = s.recv(1024)
        print("Recv:", len(data), binascii.b2a_hex(data))
        raw = decrypt_cipher_state.decrypt_with_ad(b"", data)
        print('Received', repr(raw))

main()

