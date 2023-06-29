# NoiseExample
Encrypted communication protocols without using TLS are possible

When it comes to encrypted communication protocols, many people think of TLS/SSL. Due to the convenience and ease of use of tools such as HTTPS, OpenSSL, and others, TLS/SSL has become the preferred choice for encrypted communication. However, there is also increasing research and analysis being done on TLS/SSL, and the related traffic can now be analyzed as well. In order to enhance security, some have even come up with "TLS over TLS," but it is said that it can also be analyzed. So, are there any other encryption protocols that can be used? The answer is yes, and here we will introduce one option: the Noise Protocol Framework.

The Noise Protocol Framework is an encryption protocol framework based on the Diffie-Hellman key exchange, which allows for easy construction of desired encryption protocols. It is highly flexible. Similar to TLS, the communicating parties exchange handshake messages, exchange Diffie-Hellman public keys, and perform a series of Diffie-Hellman operations, with the hashed Diffie-Hellman result serving as the shared key. After the handshake phase, encrypted transport messages can be sent using this shared secret key.

Noise supports handshake patterns where each party has long-term static key pairs and/or ephemeral key pairs. The handshake protocol can be customized using a simple language to define message formats. The simplest process requires only two steps to establish the encrypted protocol handshake, after which encrypted communication can be realized. This very new protocol framework adopts many state-of-the-art algorithms and has strong scalability. It is concise, efficient, and highly customizable.
Below is a simple example using Python's Dissononce library. After establishing a socket connection, the handshake is completed in two steps, and then encrypted communication can take place:

Here is the code: https://github.com/QunL/NoiseExample/commit/4975512b338129a4b5acc1983356e85146d44c36 

Then let's have a brief introduction to the authentication process with Noise. In the typical communication process, the client needs to verify whether the server is a legitimate server. The usual practice is to provide the client with the server's public key. If the server uses the wrong key pair, the handshake cannot be completed. Noise provides convenient support for this.

However, the NXHandshakePattern mentioned in the above does not support server-side public key authentication. This authentication pattern is not sufficiently secure. It is recommended to use handshake patterns such as XK, XX, KK, KX, IK, IX, etc. Here is an example using the IKHandshakePattern:

First, the server generates a public-private key pair:
```
import binascii
from dissononce.dh.x25519.x25519 import X25519DH

if __name__ == "__main__":
    skey = X25519DH().generate_keypair()
    print("server public key:", binascii.b2a_hex(skey.public.data))
    print("server private key:", binascii.b2a_hex(skey.private.data))
```

For example:
```
server public key: b'e53bb70c354b60d62a0bace9f897b76dcf11f4151feab245ed903175c57a3f12'
server private key: b'106bb0f0d68f0809a7341071df9e2f76b63b1149aafc213192a6e8b077b83f45'
```

The public key is transmitted to the client through a certain encoding method, such as the above HEX encoding, or it can be encoded using base58 or other methods. Then it can be passed to the client via a URL or other means.

The client needs to prepare its own key pair and the server's public key, and then specify the IK handshake protocol. 

The server needs to load its own private key and use the IK handshake protocol.

The code is here: https://github.com/QunL/NoiseExample/commit/f50c5a1a7605698d636cd89b8ec74bd847370d67 

Of course, in the scenario where the client only has a trusted CA public key certificate and wants to verify the server's public key certificate using this CA, the application needs to implement it on its own. It involves passing the CA certificate, transmitting the server certificate through Noise, and performing the verification process independently.

