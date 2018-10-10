# 密码学
> 使用GO语言实现对称加密与非对称加密

####  对称加密

- DES
- AES
- 3DES

##### 分组加密模式

> 什么是分组密码?
>
> 每次只能处理特定长度的数据,需要对明文进行分组,分组之后得到块数据,块数据分别于秘钥进行运算加密.DES,AES这类密码算法加密的块数据是分组密码.

1. ECB
   - 最后分组块不满需要手动填充,AES 16字节,DES8字节
2. CBC
   - 最后分组块不满需要手动填充,AES 16字节,DES8字节
3. CFB
   - 最后分组块无序填充
4. OFB
   - 最后分组块无序填充
5. CTR
   - 最后分组块无序填充
6. 按位异或

#### 非对称加密

- RSA
  - 生成的秘钥长度会影响需要加密数据信息的长度,RSA非对称加密适用于加密短数据.

#### 单向散列函数

> 常用的单向散列函数

- MD4/MD5
  - 不安全
- sha1
  - 不安全
- sha2
  - 安全

