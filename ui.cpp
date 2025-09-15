#include "common.hpp"

// --- UI & Utility Functions ---

void clear_screen() {
    // Standard ANSI escape code to clear screen and move cursor to top-left
    std::cout << "\033[2J\033[1;1H";
}

void print_header() {
    clear_screen();
    std::cout << BOLD << CYAN << R"(
                                                    
@@@  @@@ @@@@@@@@ @@@@@@@  @@@@@@@ @@@  @@@ @@@@@@@ 
@@!@!@@@ @@!        @!!   !@@      @@!  @@@   @!!   
@!@@!!@! @!!!:!     @!!   !@!      @!@  !@!   @!!   
!!:  !!! !!:        !!:   :!!      !!:  !!!   !!:   
::    :  : :: ::     :     :: :: :  :.:: :     :    
                                                    
                             )" << RESET << std::endl;
    std::cout << BOLD << YELLOW << "        A tool for authorized ARP spoofing tests." << RESET << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;
}

void main_menu() {
    print_header();
    std::cout << BOLD << "Main Menu:" << RESET << std::endl;
    std::cout << "1. Scan Network" << std::endl;
    std::cout << "2. View Known Devices" << std::endl;
    std::cout << "3. Start LAN Isolation Attack" << std::endl;
    std::cout << "4. Exit" << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Enter your choice: ";
}

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

void display_scan_results() {
    print_header();
    std::cout << BOLD << GREEN << "Available Targets:" << RESET << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << BOLD << std::left << std::setw(5) << "ID" << std::setw(20) << "IP Address" << std::setw(20) << "MAC Address" << RESET << std::endl;
    std::cout << "----------------------------------------------------" << std::endl;
    if (hosts.empty()) {
        std::cout << RED << "No hosts found. Perform a scan first." << RESET << std::endl;
    } else {
        for (size_t i = 0; i < hosts.size(); ++i) {
            std::cout << std::left << std::setw(5) << i + 1 << std::setw(20) << hosts[i].ip << std::setw(20) << hosts[i].mac << std::endl;
        }
    }
    std::cout << "----------------------------------------------------" << std::endl;
}


// --- Main Program Entry Point ---

int main() {
    if (geteuid() != 0) {
        std::cerr << RED << "Error: This program must be run with sudo privileges." << RESET << std::endl;
        return 1;
    }
    
    // Initial setup
    get_active_interface();
    // load_oui_from_manuf(); // Uncomment if you have the 'manuf' file
    // load_database();       // Uncomment to load previous session data

    while (true) {
        main_menu();
        int choice;
        std::cin >> choice;
        if (!std::cin) { // Handle non-integer input
            std::cin.clear();
            std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
            continue;
        }
        // Consume the rest of the line (e.g., the newline character)
        std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');

        switch (choice) {
            case 1:
                print_header();
                std::cout << GREEN << "Scanning on " << active_interface.name << "..." << RESET << std::endl;
                scan_network();
                std::cout << "\nScan complete. Found " << hosts.size() << " devices." << std::endl;
                std::cout << "\nPress Enter to continue...";
                std::cin.get();
                break;
            case 2:
                display_known_devices();
                break;
            case 3:
                start_lan_isolation_attack();
                break;
            case 4:
                // save_database(); // Uncomment to save data on exit
                std::cout << "Exiting." << std::endl;
                return 0;
            default:
                std::cout << RED << "Invalid choice. Please try again." << RESET << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds(1));
                break;
        }
    }
    return 0;
}