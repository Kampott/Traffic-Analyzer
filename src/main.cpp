#include <iostream>
#include <stdexcept>
#include "PacketSniffer.h"

int main(int argc, char* argv[]) {
    try {
        PacketSniffer sniffer;

        if (argc < 2) {
            throw std::runtime_error("Использование: " + std::string(argv[0]) + " <live|pcap> [файл.pcap]");
        }

        std::string mode = argv[1];

        if (mode == "live") {
            sniffer.startLiveCapture();
        } else if (mode == "pcap" && argc == 3) {
            sniffer.startPcapCapture(argv[2]);
        } else {
            throw std::runtime_error("Некорректные аргументы! Используйте live или pcap <файл>");
        }

        sniffer.saveToCSV("traffic_report.csv");

    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }

    return 0;
}