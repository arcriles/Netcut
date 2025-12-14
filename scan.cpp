#include "common.hpp"

// --- Global Variable Definitions ---
std::vector<Host> hosts;
std::map<std::string, DeviceInfo> device_database;
Interface active_interface;
const std::string DB_FILENAME = "netcut_db.csv";
std::map<std::string, std::string> oui_map;

// --- Helper Functions (Moved from old ui.cpp) ---
void string_mac_to_bytes(unsigned char* byte_array, const std::string& mac_str) {
    sscanf(mac_str.c_str(), "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &byte_array[0], &byte_array[1], &byte_array[2],
           &byte_array[3], &byte_array[4], &byte_array[5]);
}

std::string bytes_mac_to_string(const unsigned char* byte_array) {
    char mac_str[18];
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            byte_array[0], byte_array[1], byte_array[2],
            byte_array[3], byte_array[4], byte_array[5]);
    return std::string(mac_str);
}

// Stub for CLI header (needed by attack.cpp)
void print_header() {
    // No-op for GUI
}

// Stub for CLI results (needed by attack.cpp)
void display_scan_results() {
    // No-op for GUI
}

// --- Utility function specific to scanning ---
std::string get_vendor(std::string mac) {
    std::transform(mac.begin(), mac.end(), mac.begin(), ::toupper);
    std::string oui_prefix = mac.substr(0, 8);
    if (oui_map.count(oui_prefix)) return oui_map[oui_prefix];
    return "Unknown Vendor";
}

// --- Setup & Database Functions ---
void load_oui_from_manuf() {
    std::ifstream manuf_file("manuf");
    if (!manuf_file.is_open()) {
        std::cout << YELLOW << "[Warning] 'manuf' file not found. Vendor lookup will be disabled." << RESET << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(2));
        return;
    }
    oui_map.clear();
    std::string line;
    while (std::getline(manuf_file, line)) {
        if (line.empty() || line[0] == '#') continue;
        size_t tab_pos = line.find('\t');
        if (tab_pos != std::string::npos) {
            std::string oui = line.substr(0, tab_pos);
            std::string vendor = line.substr(tab_pos + 1);
            oui.erase(std::remove_if(oui.begin(), oui.end(), ::isspace), oui.end());
            if (oui.length() >= 8) oui_map[oui.substr(0, 8)] = vendor;
        }
    }
    manuf_file.close();
}

void load_database() {
    std::ifstream db_file(DB_FILENAME);
    if (!db_file.is_open()) return;
    std::string line;
    while (std::getline(db_file, line)) {
        std::stringstream ss(line);
        std::string mac, ip, vendor;
        if (std::getline(ss, mac, ',') && std::getline(ss, ip, ',') && std::getline(ss, vendor)) {
            device_database[mac] = {ip, vendor};
        }
    }
    db_file.close();
}

void save_database() {
    std::ofstream db_file(DB_FILENAME);
    if (!db_file.is_open()) { std::cerr << "Error: Could not save to database file." << std::endl; return; }
    for (const auto& pair : device_database) {
        db_file << pair.first << "," << pair.second.last_ip << "," << pair.second.vendor << std::endl;
    }
    db_file.close();
}

// --- Core Networking Functions for Scanning ---
void get_active_interface() {
    struct ifaddrs *ifaddr, *ifa;
    if (getifaddrs(&ifaddr) == -1) { perror("getifaddrs"); exit(EXIT_FAILURE); }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_INET && !(ifa->ifa_flags & IFF_LOOPBACK) && (ifa->ifa_flags & IFF_UP)) {
            active_interface.name = ifa->ifa_name;
            active_interface.ip = inet_ntoa(((struct sockaddr_in *)ifa->ifa_addr)->sin_addr);
            active_interface.index = if_nametoindex(ifa->ifa_name);
            break;
        }
    }
    if (active_interface.name.empty()) { std::cerr << RED << "Error: No active network interface found." << RESET << std::endl; exit(EXIT_FAILURE); }
    
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    strncpy(ifr.ifr_name, active_interface.name.c_str(), IFNAMSIZ-1);
    ioctl(sock, SIOCGIFHWADDR, &ifr);
    close(sock);
    active_interface.mac = bytes_mac_to_string((unsigned char*)ifr.ifr_hwaddr.sa_data);
    freeifaddrs(ifaddr);
}

void scan_network() {
    int sock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sock < 0) { perror("socket"); return; }

    struct timeval timeout = {0, 200000};
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    unsigned char buffer[sizeof(struct ethhdr) + sizeof(struct arp_header)];
    struct ethhdr* eth = (struct ethhdr*)buffer;
    struct arp_header* arp = (struct arp_header*)(buffer + sizeof(struct ethhdr));
    
    string_mac_to_bytes(eth->h_source, active_interface.mac);
    memset(eth->h_dest, 0xff, 6);
    eth->h_proto = htons(ETH_P_ARP);
    
    *arp = {htons(ARPHRD_ETHER), htons(ETH_P_IP), 6, 4, htons(ARPOP_REQUEST)};
    string_mac_to_bytes(arp->sender_mac, active_interface.mac);
    inet_pton(AF_INET, active_interface.ip.c_str(), arp->sender_ip);
    memset(arp->target_mac, 0x00, 6);

    std::string ip_prefix = active_interface.ip.substr(0, active_interface.ip.rfind('.') + 1);
    for (int i = 1; i < 255; ++i) {
        std::string target_ip_str = ip_prefix + std::to_string(i);
        if (target_ip_str == active_interface.ip) continue;
        inet_pton(AF_INET, target_ip_str.c_str(), arp->target_ip);
        struct sockaddr_ll sll = {0}; sll.sll_ifindex = active_interface.index;
        sendto(sock, buffer, sizeof(buffer), 0, (struct sockaddr*)&sll, sizeof(sll));
    }
    
    std::cout << BLUE << "[i] Listening for ARP replies for 3 seconds..." << RESET << std::endl;
    auto start_time = std::chrono::steady_clock::now();
    std::set<Host> found_hosts;
    while (std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() - start_time).count() < 3) {
        if (recv(sock, buffer, sizeof(buffer), 0) > 0) {
            if (ntohs(arp->opcode) == ARPOP_REPLY) {
                char ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, arp->sender_ip, ip_str, sizeof(ip_str));
                found_hosts.insert({std::string(ip_str), bytes_mac_to_string(arp->sender_mac)});
            }
        }
    }
    close(sock);

    hosts.assign(found_hosts.begin(), found_hosts.end());
    for(const auto& host : hosts) {
        if (device_database.count(host.mac)) {
            device_database[host.mac].last_ip = host.ip;
        } else {
            device_database[host.mac] = {host.ip, get_vendor(host.mac)};
        }
    }
}

// --- Menu Option Logic (extracted from main) ---
void display_known_devices() {
    print_header();
    std::cout << BOLD << GREEN << "Known Devices in Database:" << RESET << std::endl;
    std::cout << "------------------------------------------------------------------" << std::endl;
    std::cout << BOLD << std::left << std::setw(20) << "MAC Address" << std::setw(20) << "Last Seen IP" << "Vendor" << RESET << std::endl;
    std::cout << "------------------------------------------------------------------" << std::endl;
    if(device_database.empty()){
        std::cout << RED << "Database is empty. Scan the network first." << RESET << std::endl;
    } else {
        for(const auto& pair : device_database){
            std::cout << std::left << std::setw(20) << pair.first << std::setw(20) << pair.second.last_ip << pair.second.vendor << std::endl;
        }
    }
    std::cout << "------------------------------------------------------------------" << std::endl;
    std::cout << "\nPress Enter to continue...";
    std::cin.get();
}

// --- NEW FUNCTION for GUI ---
std::string resolve_hostname(const std::string& ip) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &sa.sin_addr);
    
    char node[NI_MAXHOST];
    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), node, sizeof(node), NULL, 0, 0) == 0) {
        return std::string(node);
    }
    return ""; 
}