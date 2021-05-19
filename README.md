# snort-parser
## Simple snort output parser written for my friend's master thesis.
It was designed to parse records stored in a file in one of the following formats:
```
04/26-15:59:21.932974 192.168.59.129:4444 -> 192.168.59.90:49168
TCP TTL:64 TOS:0x0 ID:30257 IpLen:20 DgmLen:168 DF
***AP*** Seq: 0xDBA1D0A5  Ack: 0x7525493A  Win: 0x1F5  TcpLen: 20
```
```
09/27-06:20:05.557801 192.168.1.1:53 -> 192.168.1.3:60384
UDP TTL:255 TOS:0x0 ID:20613 IpLen:20 DgmLen:140 DF
Len: 112
```
