# Challenge 17

## 理解题目

某系统提供加密和解密两个函数：
1. 加密函数 encrypt(), 使用AES-CBC-PKCS7算法，加密一段数据unkown_str，返回密文和初始向量(cipher, iv)
2. 解密函数 decrypt(cipher, iv)，使用与encrypt() 相同的密钥和算法解密密文并检查明文的PKCS7padding是否合法。合法padding 返回true，非法padding返回false
已知cipher，iv，仅使用decrypt函数破解unkown_str。

## 思路

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

# Challenge 23

## 理解题目

mt19937算法生成伪随机数的方法:
- 步骤1，初始化。根据seed，初始化一个包含624个元素的状态数组state[624]
- 步骤2，更新state状态数组的全部元素
- 步骤3，取状态数组中的下一个元素，执行temper()，作为下一个伪随机输出，直到状态数组中的所有元素被使用，跳转到步骤2
其中temper()函数是可逆的，所以给定这样的一组伪随机数，可以倒推状态数组。得到状态数组之后，即可预测后续的伪随机数序列。

## 思路

根据wikipedia内容，temper()函数算法如下：
```
int x := MT[index]
    y := x xor (right shift by 11 bits(x))
    z := y xor (left shift by 7 bits(y) and (2636928640)) // 2636928640 == 0x9d2c5680
    u := z xor (left shift by 15 bits(z) and (4022730752)) // 4022730752 == 0xefc60000
    v := u xor (right shift by 18 bits(u))
return v
```

第1，4行的运算为`y = x ^ (x >> n)`。x，y是32位整数，n表示移位的个数（1 <= n <= 31）。分别用x[i], y[i]
表示x和y的第i位（0 <= i <= 31)，则运算如下：

```
          x[31]        ...       x[n]      // x >> n
x[31] ... x[31-n]      ...       x[0]      // x
----------------- ^ -----------------
y[31] ... y[31-n]      ...       y[0]      // y
```

可以看出:
- y[i] = x[i]，         当 i > 31-n；
- y[i] = x[i] ^ x[i+n]，当 i <= 31-n。

已知y的情况下，求x：

- x[i] = y[i]，         当 i > 31-n;
- x[i] = y[i] ^ x[i+n]，当 i <= 31-n（从高位向低位，计算x[i]时，x[i+n]已经算出）。

n有两种特殊情况：
- 当n=0时，`y = x ^ (x >> 0) = x ^ x = 0`，任何整数异或自己都等于0，已知y无法求解x
- 当n>=32时，`y = x ^ (x >> 32) = x ^ 0 = x`，y即为x

所以第1，4行的逆运算为：

```
def reverse_rshift_xor(y, n):
    assert n != 0

    if n >= 32:
        return y

    x = y & ~((1 << (32-n)) - 1)
    for i in range(31 - n, -1, -1):
        x |= (y ^ (x >> n)) & (1 << i)

    return x
```

第2，3行的运算为`y = x ^ ((x << n) & m)`。x, y为32位整数，n为左移位数（1 <= n <= 31），m是魔数且m的最低n位都是0.
分别用x[i]，y[i]，m[i]来表示x，y和m的每一位，则该运算示意如下：

```
x[31-n] ... x[0]                    // x << n
m[31]   ... m[n]                    // m
---------------- & --------------

x[31]   ... x[n]     ...     x[0]   // x
---------------- ^ --------------
y[31]   ... y[n]     ...     y[0]   // y
```

可以看出：
- y[i] = x[i]，                  当i < n；
- y[i] = x[i] ^ (x[i-n] & m[i])，当i >= n。

已知y, n, m的情况下，求解x：
- x[i] = y[i]                    当i < n；
- x[i] = y[i] ^ (x[i-n] & m[i])  当i >= n（从低位向高位，计算x[i]时，x[i-n]已经算出）。

所以第2，3行的逆运算：

```
def reverse_lshift_xor(y, n, m):
    assert n != 0

    if n >= 32:
        return y

    x = y & ((1 << n) - 1)
    for i in range(n, 32):
        x |= (y ^ ((x << n) & m)) & (1 << i)

    return x
```

# Challenge 24

## 理解题目

使用mt19937伪随机数生成器实现一个流密码算法，算法使用16位的密钥作为伪随机数生成器的种子，用这个流密码算法加密一段明文。
利用密文，恢复出密钥。

## 思路

由于密钥是16 bit，直接暴力破解即可。