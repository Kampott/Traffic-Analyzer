#include "PacketSniffer.h"
#include <iostream>
#include <fstream>
#include <pcap.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

PacketSniffer::PacketSniffer() : handle(nullptr, &pcap_close) {}

void PacketSniffer::startLiveCapture() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        throw std::runtime_error("Ошибка pcap_findalldevs: " + std::string(errbuf));
    }

    std::cout << "Введите количество пакетов для захвата: ";
    int packet_limit;
    std::cin >> packet_limit;

    std::cout << "Выберите интерфейс:\n";
    int i = 0;
    for (pcap_if_t* d = alldevs; d; d = d->next, i++) {
        std::cout << i << ": " << (d->name ? d->name : "Нет имени") << std::endl;
    }

    int choice;
    std::cin >> choice;
    pcap_if_t* selected_dev = alldevs;
    for (int j = 0; j < choice && selected_dev; j++) {
        selected_dev = selected_dev->next;
    }
    if (!selected_dev) {
        pcap_freealldevs(alldevs);
        throw std::runtime_error("Ошибка выбора интерфейса!");
    }
    handle.reset(pcap_open_live(selected_dev->name, BUFSIZ, 1, 1000, errbuf));

    if (!handle) {
        throw std::runtime_error("Ошибка pcap_open_live: " + std::string(errbuf));
    }
    std::cout << "[DEBUG] Захват трафика на интерфейсе: " << selected_dev->name << " (" << packet_limit << " пакетов)" << std::endl;
    pcap_freealldevs(alldevs);

    struct bpf_program filter;
    if (pcap_compile(handle.get(), &filter, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle.get(), &filter) == -1) {
        throw std::runtime_error("[ERROR] Ошибка установки BPF-фильтра!");
    }
    pcap_set_immediate_mode(handle.get(), 1);
    pcap_loop(handle.get(), packet_limit, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketSniffer::startPcapCapture(const std::string& filename) {
    char errbuf[PCAP_ERRBUF_SIZE];
    handle.reset(pcap_open_offline(filename.c_str(), errbuf));

    if (!handle) {
        throw std::runtime_error("Ошибка открытия PCAP-файла: " + std::string(errbuf));
    }

    std::cout << "[DEBUG] Чтение пакетов из файла: " << filename << std::endl;
    struct bpf_program filter;
    if (pcap_compile(handle.get(), &filter, "ip", 0, PCAP_NETMASK_UNKNOWN) == -1 ||
        pcap_setfilter(handle.get(), &filter) == -1) {
        throw std::runtime_error("[ERROR] Ошибка установки BPF-фильтра!");
    }
    pcap_set_immediate_mode(handle.get(), 1);
    pcap_loop(handle.get(), 100, packetHandler, reinterpret_cast<u_char*>(this));
}

void PacketSniffer::processPacket(const struct pcap_pkthdr* header, const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14);
    if (ip_header->ip_v != 4) return;

    std::string src_ip = inet_ntoa(ip_header->ip_src);
    std::string dst_ip = inet_ntoa(ip_header->ip_dst);
    uint16_t src_port = 0, dst_port = 0;
    std::string protocol = "OTHER";

    if (ip_header->ip_p == IPPROTO_TCP) {
        struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(tcp_header->th_sport);
        dst_port = ntohs(tcp_header->th_dport);
        protocol = "TCP";
    } else if (ip_header->ip_p == IPPROTO_UDP) {
        struct udphdr* udp_header = (struct udphdr*)(packet + 14 + (ip_header->ip_hl * 4));
        src_port = ntohs(udp_header->uh_sport);
        dst_port = ntohs(udp_header->uh_dport);
        protocol = "UDP";
    } else {
        return;
    }

    std::string flow_key = src_ip + "," + dst_ip + "," +std::to_string(src_port) + 
                             + "," + std::to_string(dst_port);
    flow_data[flow_key].first += 1;
    flow_data[flow_key].second += header->len;

    std::cout << "[DEBUG] " << protocol << " Пакет: " << src_ip << ":" << src_port
              << " -> " << dst_ip << ":" << dst_port << " | Размер: " << header->len << " байт" << std::endl;
}

void PacketSniffer::saveToCSV(const std::string& filename) {
    std::ofstream csv_file(filename, std::ios::trunc);
    if (!csv_file) {
        throw std::runtime_error("[ERROR] Ошибка открытия CSV-файла!");
    }

    csv_file << "Source IP,Dest IP,Source Port,Dest Port,Packet Count,Byte Count\n";

    for (const auto& entry : flow_data) {
        csv_file << entry.first << "," << entry.second.first << "," << entry.second.second << "\n";
    }
}

void PacketSniffer::packetHandler(u_char* userData, const struct pcap_pkthdr* header, const u_char* packet) {
    PacketSniffer* sniffer = reinterpret_cast<PacketSniffer*>(userData);
    sniffer->processPacket(header, packet);
}