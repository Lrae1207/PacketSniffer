# Compiles and executes the program
g++ sniffer.cpp sniffer.hpp colors.hpp -lpcap -o packet_sniffer
sudo ./packet_sniffer
rm packet_sniffer
