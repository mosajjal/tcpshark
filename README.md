# TCPShark (WIP)

```sh
git clone https://github.com/mosajjal/tcpshark
cd tcpshark
go get
go build .
sudo ./tcpshark -i enp2s0f0 -o /dev/stdout -v 2 | wireshark -X lua_script:tcpshark.lua -Y tcpshark -k -i -
```