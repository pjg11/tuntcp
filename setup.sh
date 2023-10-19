sudo ip tuntap del tun0 mode tun
sudo ip tuntap add name tun0 mode tun user $USER
sudo ip link set tun0 up
sudo ip addr add 192.0.2.1 peer 192.0.2.2 dev tun0

#sudo iptables -t nat -A POSTROUTING -s 192.0.2.2 -j MASQUERADE
#sudo iptables -A FORWARD -i tun0 -s 192.0.2.2 -j ACCEPT
#sudo iptables -A FORWARD -o tun0 -d 192.0.2.2 -j ACCEPT
#sudo sysctl -w net.ipv4.ip_forward=1
