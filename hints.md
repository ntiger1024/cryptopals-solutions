# Challenge 17

题目：某系统提供加密和解密两个函数：
1. 加密函数 encrypt(), 使用AES-CBC-PKCS7算法，加密一段数据unkown_str，返回密文和初始向量(cipher, iv)
2. 解密函数 decrypt(cipher, iv)，使用与encrypt() 相同的密钥和算法解密密文并检查明文的PKCS7padding是否合法。合法padding 返回true，非法padding返回false
已知cipher，iv，仅使用decrypt函数破解unkown_str。

AES-CBC-PKCS7的加密过程如下：
1. 使用PKCS7 padding对待加密的明文进行补充，PKCS7 padding的特点是，如果明文是块大小的整数倍，则补充一个整块，每个字节的值为块大小；如果明文不是块大小的整数倍，则补充x个值为x的字节，使其变成块大小的整数倍
2. 使用CBC模式加密：cipher_block[i] = AES_encrypt(plain_block[i] ^ cipher_block[i-1])。

AES-CBC-PKCS7的解密过程如下：
1. 使用CBC模式解密：plain_block[i] = AES_decrypt(cipher_block[i]) ^ cipher_block[i-1]。CBC解密的一个特性是，修改cipher_block[i-1]的一个bit，会导致plain_block[i]的同一个bit被修改
2. 检查PKCS7 padding是否有效，并去除合法的padding，得到原始明文。PKCS7 padding的特点是，如果明文是块大小的整数倍，则补充一个整块，每个字节的值为块大小；如果明文不是块大小的整数倍，则补充x个值为x的字节，使其变成块大小的整数倍

根据CBC和PKCS7 padding的特点，可以按如下方法破解密文：
- 从第一个密文块开始单独解密每一个块。以cipher_block[0]为例，其对应的cipher_block[i-1]是初始向量IV。
    - 对于最后一个字节，如果plain_block[0][15]的值为0x01，则当plain_block[0][14]不为0x01时，decrypt()函数认为是一个合法的padding，返回true。
        - 我们修改IV的最后一个字节IV[15]，遍历所有可能的值（0-255），当decrypt()函数返回true时:
        ```
        AES_decrypt(cipher_block[0])[15] ^ IV[15] = 0x01，=>
        AES_decrypt(cipher_block[0])[15]          = IV[15] ^ 0x01，=>
        plain_block[0][15]                        = IV[15] ^ 0x01 ^ origin_IV[15]
        ```
        - 遍历IV[15]所有可能值进行解密的时候，可能出现其他合法的padding，例如最后两个字节是`b'\x02\x02`。为了防止这种情况出现，分别设置不同的IV[14]调用decrypt()函数两次，如果两次都返回True，则找到了正确的padding`b\x01`。
    - 对于最后两个字节。如果plain_block[0][14:15]的值为0x02,0x02，则当[0][13]不为0x02时，decrypt()函数认为是一个合法padding，返回true。
        - 修改IV的最后一个字节IV[15]，使其与cipher_block[0][15]的异或为0x02；
        - 修改IV的IV[14]，遍历所有可能的值，找到使decrypt()函数返回true的值：
        ```
        IV[15] = AES_decrypt(cipher_block[0])[15] ^ 0x02

        AES_decrypt(cipher_block[0])[14] ^ IV[14] = 0x02，=>
        AES_decrypt(cipher_block[0])[14]          = IV[14] ^ 0x02，=>
        plain_block[0][14]                        = IV[14] ^ 0x01 ^ origin_IV[14]
        ```
        - 同样的，为了防止出现`b\x03\x03\x03`等其他合法padding，分别设置不同的IV[13]调用decrypt()两次。
- 以此类推，即可计算出所有明文。

算法：
```
def break_cbc_padding_oracle(cipher, iv, block_size):
    """Break the cbc padding oracle funtions."""
    plain = bytearray(len(cipher))
    blocks = len(cipher) // block_size
    orig_prev_block = bytearray(iv)
    prev_block = orig_prev_block[:]
    for i in range(blocks):
        intermediate = bytearray(block_size)
        cipher_block = cipher[i * block_size: i * block_size + block_size]
        for j in range(block_size - 1, -1, -1):
            padding_byte = block_size - j
            for k in range(j + 1, block_size):
                prev_block[k] = intermediate[k] ^ padding_byte
            for k in range(256):
                prev_block[j] = k
                if j > 0:
                    prev_block[j-1] = (k + 1) % 256
                if cbc_padding_oracle_decrypt(cipher_block, prev_block) is True:
                    if j > 0:
                        prev_block[j-1] = (k + 2) % 256
                    if cbc_padding_oracle_decrypt(cipher_block, prev_block) is True:
                        intermediate[j] = prev_block[j] ^ padding_byte
                        plain[i * block_size + j] = intermediate[j] ^ orig_prev_block[j]
                        break
        orig_prev_block = bytearray(cipher_block)
        prev_block = orig_prev_block[:]
    return pkcs7depadding(plain, 16)
```