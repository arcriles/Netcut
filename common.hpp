#ifndef COMMON_HPP
#define COMMON_HPP

#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <chrono>
#include <atomic>
#include <iomanip>
#include <map>
#include <set>
#include <sstream>
#include <algorithm>
#include <random>
#include <fstream>
#include <cstdio>
#include <limits>

// C headers for low-level networking
#include <cstring>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/if_arp.h>

// --- ANSI Color Codes ---
#define RESET   "\033[0m"
#define BOLD    "\033[1m"
#define RED     "\033[31m"
#define GREEN   "\033[32m"
#define YELLOW  "\033[33m"
#define BLUE    "\033[34m"
#define CYAN    "\033[36m"

// --- Data Structures ---
struct Host {
    std::string ip;
    mutable std::string mac;
    bool operator<(const Host& other) const { return ip < other.ip; }
};

struct DeviceInfo {
    std::string last_ip;
    std::string vendor;
};

struct Interface {
    std::string name, ip, mac;
    int index = -1;
};

struct arp_header {
    uint16_t hardware_type, protocol_type;
    uint8_t  hardware_len, protocol_len;
    uint16_t opcode;
    uint8_t  sender_mac[6], sender_ip[4], target_mac[6], target_ip[4];
};

// --- Global Variable Declarations (Shared across files) ---
extern std::vector<Host> hosts;
extern std::map<std::string, DeviceInfo> device_database;
extern Interface active_interface;
extern const std::string DB_FILENAME;
extern std::map<std::string, std::string> oui_map;
// --- UNUSED CODE START ---
// The following two maps are defined in attack.cpp but are not currently
// used by any function. Local variables are used instead.
extern std::map<std::string, std::thread> active_attack_threads;
extern std::map<std::string, std::atomic<bool>> attack_signals;
// --- UNUSED CODE END ---


// --- Function Prototypes ---

// From scan.cpp
void get_active_interface();
void scan_network();
void load_oui_from_manuf();
void load_database();
void save_database();
void display_known_devices();

// From attack.cpp and attack1.cpp
void start_lan_isolation_attack();
void start_mitm_attack(); // <-- Fix applied here

// From ui.cpp
void print_header();
void main_menu();
void display_scan_results();
std::string bytes_mac_to_string(const unsigned char* byte_array);
void string_mac_to_bytes(unsigned char* byte_array, const std::string& mac_str);


#endif // COMMON_HPP