Project Goal
To analyze the aftermath of the DarkInjector ransomware attack, recover encrypted files, and extract the final flag. The main objective was to exploit a vulnerability in a weak 128-bit RSA key to recover the AES key used for encryption.

Initial Situation
On the target machine, two files were found in /tmp:

public_key.txt — containing RSA modulus n and exponent e

encrypted_aes_key.bin — a binary file containing the AES key encrypted with RSA

RSA Key Analysis

n = 340282366920938460843936948965011886881
e = 65537
The modulus n is only 128 bits long, which makes it extremely vulnerable to factorization attacks.

Analyzing the Binary File

hexdump -C encrypted_aes_key.bin
Output:
00000000  0e f7 8a 76 75 2e 28 74  24 97 3c 54 41 49 6f 9f
Factoring the RSA Modulus
Used Fermat’s method or dcode.fr/rsa-cipher to factor n:

p = 18446744073709551557
q = 18446744073709551663
Then compute φ(n):

φ(n) = (p - 1) * (q - 1)
And calculate the private key d = e⁻¹ mod φ(n).

Entered these values into dcode.fr → obtained:

Decrypted AES key = 26301178412774673439707015133001453321

Decrypting the Files
Used the AES key either manually or via the provided decryption interface. Successfully opened:

/home/ubuntu/Desktop/student_grades.docx
Flag
THM{d0nt_l34k_y0ur_w34k_m0dul5}

Conclusion
Weak RSA (128-bit) can be factored in seconds

Recovering the private key d allows decrypting the AES key

All ransomware-encrypted files were successfully recovered without paying any ransom

Confirmed: Improper cryptographic implementation leads to total data compromise
