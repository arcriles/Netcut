#include <QApplication>
#include <QMainWindow>
#include <QTableWidget>
#include <QPushButton>
#include <QVBoxLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QHeaderView>
#include <QThread>
#include <QMessageBox>
#include <QDebug>
#include "common.hpp"

class ScanWorker : public QThread {
    Q_OBJECT
public:
    void run() override {
        scan_network(); 
        emit scanFinished();
    }
signals:
    void scanFinished();
};

class AttackWorker : public QThread {
    Q_OBJECT
    std::vector<std::string> targets;
    std::string gateway;
    std::atomic<bool>* signal;
public:
    AttackWorker(std::vector<std::string> t, std::string g, std::atomic<bool>* s) 
        : targets(t), gateway(g), signal(s) {}
    
    void run() override {
        run_mitm_attack_gui(targets, gateway, signal);
        emit attackFinished();
    }
signals:
    void attackFinished();
};

class NetcutGUI : public QMainWindow {
    Q_OBJECT
    QTableWidget* table;
    QPushButton* btnScan;
    QPushButton* btnCut;
    QPushButton* btnStop;
    QLabel* statusLabel;
    
    ScanWorker* scanWorker;
    AttackWorker* attackWorker;
    std::atomic<bool> attackSignal;

public:
    // Reordered initializer list to match declaration order
    NetcutGUI() : scanWorker(nullptr), attackWorker(nullptr), attackSignal(false) {
        setWindowTitle("Netcut GUI");
        resize(900, 600);
        
        QWidget* central = new QWidget;
        setCentralWidget(central);
        QVBoxLayout* layout = new QVBoxLayout(central);

        // 1. Table Setup
        table = new QTableWidget();
        table->setColumnCount(4);
        table->setHorizontalHeaderLabels({"IP Address", "MAC Address", "Vendor", "Device Name"});
        table->horizontalHeader()->setSectionResizeMode(QHeaderView::Stretch);
        table->setSelectionBehavior(QAbstractItemView::SelectRows);
        table->setEditTriggers(QAbstractItemView::NoEditTriggers); 
        layout->addWidget(table);

        // 2. Control Panel
        QHBoxLayout* controls = new QHBoxLayout();
        btnScan = new QPushButton("Scan Network");
        btnCut = new QPushButton("Cut Off (MITM)");
        btnStop = new QPushButton("Stop Attack");
        btnStop->setEnabled(false);
        
        btnCut->setStyleSheet("background-color: #ffcccc; color: red; font-weight: bold;");
        btnStop->setStyleSheet("font-weight: bold;");

        controls->addWidget(btnScan);
        controls->addWidget(btnCut);
        controls->addWidget(btnStop);
        layout->addLayout(controls);

        statusLabel = new QLabel("Ready. Run as Root.");
        layout->addWidget(statusLabel);

        // 3. Logic Initialization
        scanWorker = new ScanWorker();
        
        connect(btnScan, &QPushButton::clicked, this, &NetcutGUI::startScan);
        connect(scanWorker, &ScanWorker::scanFinished, this, &NetcutGUI::onScanFinished);
        
        connect(btnCut, &QPushButton::clicked, this, &NetcutGUI::startAttack);
        connect(btnStop, &QPushButton::clicked, this, &NetcutGUI::stopAttack);

        // 4. Initial Global Setup
        get_active_interface(); 
        load_oui_from_manuf();
        
        statusLabel->setText(QString("Interface: %1 (%2)").arg(QString::fromStdString(active_interface.name), QString::fromStdString(active_interface.ip)));
    }

private slots:
    void startScan() {
        statusLabel->setText("Scanning network... Please wait.");
        btnScan->setEnabled(false);
        btnCut->setEnabled(false);
        table->setRowCount(0);
        scanWorker->start();
    }

    void onScanFinished() {
        statusLabel->setText(QString("Scan Complete. Found %1 devices.").arg(hosts.size()));
        btnScan->setEnabled(true);
        btnCut->setEnabled(true);
        
        table->setRowCount(hosts.size());
        for(size_t i=0; i<hosts.size(); ++i) {
            table->setItem(i, 0, new QTableWidgetItem(QString::fromStdString(hosts[i].ip)));
            table->setItem(i, 1, new QTableWidgetItem(QString::fromStdString(hosts[i].mac)));
            
            std::string vendor = "Unknown";
            if(!hosts[i].mac.empty()) {
                std::string prefix = hosts[i].mac.substr(0, 8); 
                std::transform(prefix.begin(), prefix.end(), prefix.begin(), ::toupper);
                if(oui_map.count(prefix)) vendor = oui_map[prefix];
            }
            table->setItem(i, 2, new QTableWidgetItem(QString::fromStdString(vendor)));

            std::string hostname = resolve_hostname(hosts[i].ip);
            if(hostname.empty()) hostname = "?";
            table->setItem(i, 3, new QTableWidgetItem(QString::fromStdString(hostname)));
        }
    }

    void startAttack() {
        auto items = table->selectedItems();
        if(items.empty()) {
            QMessageBox::warning(this, "Target Error", "Please select at least one target device from the list.");
            return;
        }

        std::vector<std::string> targets;
        std::set<int> rows;
        for(auto* item : items) rows.insert(item->row());
        
        for(int row : rows) {
            QString ip = table->item(row, 0)->text();
            targets.push_back(ip.toStdString());
        }

        std::string gateway_ip;
        FILE *fp = popen("ip r | grep default | cut -d' ' -f3", "r");
        char buf[16];
        if (fp && fgets(buf, sizeof(buf), fp) != NULL) gateway_ip = buf;
        if(fp) pclose(fp);
        gateway_ip.erase(std::remove(gateway_ip.begin(), gateway_ip.end(), '\n'), gateway_ip.end());

        if(gateway_ip.empty()) {
             QMessageBox::critical(this, "Network Error", "Could not find Default Gateway.");
             return;
        }

        attackSignal.store(true);
        attackWorker = new AttackWorker(targets, gateway_ip, &attackSignal);
        
        connect(attackWorker, &AttackWorker::attackFinished, this, [this](){
            statusLabel->setText("Attack Stopped. Network recovered.");
            btnCut->setEnabled(true);
            btnStop->setEnabled(false);
            btnScan->setEnabled(true);
            attackWorker->deleteLater();
            attackWorker = nullptr;
        });

        attackWorker->start();
        
        statusLabel->setText("Attacking " + QString::number(targets.size()) + " Targets...");
        btnCut->setEnabled(false);
        btnScan->setEnabled(false);
        btnStop->setEnabled(true);
    }

    void stopAttack() {
        if(attackWorker) {
            attackSignal.store(false);
            statusLabel->setText("Stopping... (Recovering ARP tables)");
            btnStop->setEnabled(false); 
        }
    }
};

int main(int argc, char *argv[]) {
    if (geteuid() != 0) {
        fprintf(stderr, "Error: Netcut GUI must run as root.\n");
        return 1;
    }
    QApplication app(argc, argv);
    NetcutGUI gui;
    gui.show();
    return app.exec();
}

#include "gui_main.moc"