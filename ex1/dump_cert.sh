openssl s_client -connect google.com:443 -showcerts  > certs_dumps.txt      
sudo tcpdump -i enp7s0 -w tls_handshake.pcap 'tcp port 443'

tshark -r tls_handshake.pcap -Y 'tls.handshake'