'''server.py with noise. liqun@outlook.com 20230512'''
import socket
import traceback
import binascii
from dissononce.cipher.chachapoly import ChaChaPolyCipher
#from dissononce.cipher.aesgcm import AESGCMCipher
from dissononce.dh.x25519.x25519 import X25519DH
from dissononce.hash.blake2s import Blake2sHash
#from dissononce.hash.sha256 import SHA256Hash
from dissononce.processing.handshakepatterns.interactive.IK import IKHandshakePattern
from dissononce.dh.private import PrivateKey
from dissononce.processing.impl.cipherstate import CipherState
from dissononce.processing.impl.handshakestate import HandshakeState
from dissononce.processing.impl.symmetricstate import SymmetricState
HOST = ''                 # Symbolic name meaning all available interfaces
PORT = 50007              # Arbitrary non-privileged port
def main():
    'main'
    prvkey_bytes = binascii.a2b_hex('106bb0f0d68f0809a7341071df9e2f76b63b1149aafc213192a6e8b077b83f45')
    server_key = X25519DH().generate_keypair(PrivateKey(prvkey_bytes))
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(1)
        while True:
            try:
                conn, addr = s.accept()
                shakehanded = False
                with conn:
                    print('Connected by', addr)
                    while True:
                        data = conn.recv(1024)
                        if not data: break
                        if not shakehanded:
                            #shakehand
                            cipher = ChaChaPolyCipher() # AESGCMCipher()
                            our_handshakestate = HandshakeState(SymmetricState(
                                                                        CipherState( cipher ),
                                                                        Blake2sHash(), # SHA256Hash
                                                                    ),
                                                                X25519DH(),)
                            prologue = b'RandomData' #Same with the client.
                            our_handshakestate.initialize(IKHandshakePattern(), False, prologue, s=server_key)
                            message_buffer = bytearray()
                            our_handshakestate.read_message(data, message_buffer)
                            print("read_message:", message_buffer, len(data))
                            if message_buffer != b'AuthDataSignedBySecKey':
                                print("Auth fail.")
                                break

                            message_buffer = bytearray()
                            cipherstates = our_handshakestate.write_message(
                                b'AuthData2SignedBySecKey', message_buffer
                            )
                            cipher_state = cipherstates[1]
                            decrypt_cipher_state = cipherstates[0]
                            data = message_buffer
                            print("Handshake done:", addr, len(data), binascii.b2a_hex(data))
                            conn.sendall(data)
                            shakehanded = True
                            continue
                        print("Recv:", len(data), binascii.b2a_hex(data))
                        data = decrypt_cipher_state.decrypt_with_ad(b"", data)
                        print("Recv text:", len(data), data)
                        data = cipher_state.encrypt_with_ad(b"", data)
                        print("Send:", len(data), binascii.b2a_hex(data))
                        conn.sendall(data)
            except:
                print("exit now", traceback.format_exc())
                break

main()

