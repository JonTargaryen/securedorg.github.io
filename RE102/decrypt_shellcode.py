import os
import sys


def key_schedule(key):
    keylength = len(key)
    S = range(256)
    j = 0
    for i in range(256):
        k = ord(key[i % keylength])
        j = (j + S[i] + k) % 256
        S[i], S[j] = S[j], S[i]  # swap
    return S, j


with open(sys.argv[1], 'rb') as key_file, open(sys.argv[2], 'rb') as encrypted, open("decrypted_shellcode.bin", 'wb') as out:
    key_size = os.path.getsize(sys.argv[1])  # 0x20
    key = key_file.read(key_size)
    S, j = key_schedule(key)

    """
    A normal RC4 stream algorithm
    resets j before a second use.
    """
    # j = 0

    i = 0

    shellcode_size = os.path.getsize(sys.argv[2])  # 0x65E4

    while (shellcode_size > 0):
        char = encrypted.read(1)
        i = (i + 1) % 256
        j = (j + S[i]) % 256

        # swap
        S[i], S[j] = S[j], S[i]
        k = S[(S[i] + S[j]) % 256]
        shellcode_size -= 1

        out.write(chr(ord(char) ^ k))
    out.close()
    key_file.close()
    encrypted.close()
