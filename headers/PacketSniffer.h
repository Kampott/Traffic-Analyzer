#ifndef PACKET_SNIFFER_H
#define PACKET_SNIFFER_H

#include <pcap.h>
#include <string>
#include <unordered_map>
#include <memory>

class PacketSniffer {
private:
    std::unique_ptr<pcap_t, decltype(&pcap_close)> handle;
    std::unordered_map<std::string, std::pair<int, int>> flow_data;

    //Функция обработки отдельного пакета
    void processPacket(const struct pcap_pkthdr* header, const u_char* packet);

    //Обработчик пакетов
    static void packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet);
public:
    PacketSniffer();

    //начать захват в реальном времени
    void startLiveCapture();

    //начать анализ pcap файла
    void startPcapCapture(const std::string& filename);

    //сохранить результат в CSV файл
    void saveToCSV(const std::string& filename);

};


#endif