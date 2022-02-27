# TCPShark (WIP)

```sh
git clone https://github.com/mosajjal/tcpshark
cd tcpshark
go get
go build .
sudo ./tcpshark -i eth0 -o /dev/stdout -v 2 | wireshark -X lua_script:tcpshark.lua -Y tcpshark -k -i -
```


run it through SSH
```
scp tcpshark HOSTNAME:/tmp/tcpshark
ssh HOSTNAME /tmp/tcpshark -i eth0 -o /dev/stdout -v 2 --bpf="'not port 22'" | wireshark -X lua_script:tcpshark.lua -Y tcpshark -k -i -
```