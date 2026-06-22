/*
 * Simplified IDS Backend Engine  (Data-Structures Edition)
 * =========================================================
 * Same inputs / outputs as the original, but now uses:
 *
 *   1. Queue          – packet ingestion buffer  (std::queue)
 *   2. Stack          – audit / event log        (std::stack)
 *   3. Linked List    – alert chain              (custom singly-linked list)
 *   4. BST            – IP stats lookup tree     (custom binary search tree)
 *   5. Max-Heap       – top-threat IP ranking    (custom array-based heap)
 *   6. Priority Queue – alert dispatch pipeline  (std::priority_queue)
 *
 * Compile:
 *   g++ -std=c++17 Simplified_IDS_Backend_DS.cpp -o ids_engine
 *
 * Run:
 *   ids_engine packets.csv
 *   ids_engine packets.csv output_folder
 *   ids_engine packets.csv output_folder --search-ip 192.168.1.50
 *   ids_engine --make-sample sample_packets.csv
 */

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iostream>
#include <queue>
#include <sstream>
#include <stack>
#include <string>
#include <vector>

using namespace std;

// ================================================================
// Helper Functions
// ================================================================

string trim(string value)
{
    int start = 0;
    int end   = (int)value.length() - 1;

    while (start < (int)value.length() && isspace((unsigned char)value[start]))
        start++;

    while (end >= start && isspace((unsigned char)value[end]))
        end--;

    if (start > end)
        return "";

    return value.substr(start, end - start + 1);
}

string toLowerCase(string value)
{
    for (int i = 0; i < (int)value.length(); i++)
        value[i] = (char)tolower((unsigned char)value[i]);
    return value;
}

int stringToInt(string value, int defaultValue)
{
    value = trim(value);
    if (value.empty()) return defaultValue;
    try { return stoi(value); }
    catch (...) { return defaultValue; }
}

bool containsText(string text, string keyword)
{
    return toLowerCase(text).find(toLowerCase(keyword)) != string::npos;
}

string joinPath(string directory, string fileName)
{
    if (directory.empty() || directory == ".")
        return fileName;
    char last = directory[directory.length() - 1];
    if (last == '/' || last == '\\')
        return directory + fileName;
    return directory + "/" + fileName;
}

vector<string> splitCSVLine(string line)
{
    vector<string> fields;
    string field;
    stringstream ss(line);
    while (getline(ss, field, ','))
        fields.push_back(trim(field));
    return fields;
}

string csvEscape(string value)
{
    string escaped;
    bool needsQuotes = false;
    for (char c : value)
    {
        if (c == '"') { escaped += "\"\""; needsQuotes = true; }
        else          { if (c == ',' || c == '\n') needsQuotes = true; escaped += c; }
    }
    return needsQuotes ? "\"" + escaped + "\"" : escaped;
}

// ================================================================
// Core Structures
// ================================================================

struct Packet
{
    int    id;
    string timestamp;
    string sourceIP;
    string destinationIP;
    int    sourcePort;
    int    destinationPort;
    string protocol;
    int    packetSize;
    string flags;
    string payload;
};

struct Alert
{
    int    id;
    string type;
    string sourceIP;
    string destinationIP;
    string message;
    string riskLevel;
    int    score;
};

struct IPStats
{
    string ip;
    int    packetCount;
    int    synCount;
    int    suspiciousPortCount;
    int    largePacketCount;
    int    keywordCount;
    int    threatScore;
    string riskLevel;
};

// ================================================================
// DATA STRUCTURE 1 – LINKED LIST
// Purpose: stores the alert chain; avoids reallocation overhead
//          and makes O(1) append natural.
// ================================================================

struct AlertNode
{
    Alert      data;
    AlertNode* next;

    AlertNode(Alert a) : data(a), next(nullptr) {}
};

struct AlertLinkedList
{
    AlertNode* head;
    AlertNode* tail;
    int        size;

    AlertLinkedList() : head(nullptr), tail(nullptr), size(0) {}

    ~AlertLinkedList()
    {
        AlertNode* cur = head;
        while (cur)
        {
            AlertNode* nxt = cur->next;
            delete cur;
            cur = nxt;
        }
    }

    // Append a new alert at the tail – O(1)
    void append(Alert a)
    {
        AlertNode* node = new AlertNode(a);
        if (!tail)
            head = tail = node;
        else
        {
            tail->next = node;
            tail       = node;
        }
        size++;
    }

    // Convert to vector for output writers
    vector<Alert> toVector() const
    {
        vector<Alert> v;
        AlertNode* cur = head;
        while (cur) { v.push_back(cur->data); cur = cur->next; }
        return v;
    }

    // Search by source or destination IP – returns matching alerts
    vector<Alert> searchByIP(const string& ip) const
    {
        vector<Alert> results;
        AlertNode* cur = head;
        while (cur)
        {
            if (cur->data.sourceIP == ip || cur->data.destinationIP == ip)
                results.push_back(cur->data);
            cur = cur->next;
        }
        return results;
    }
};

// ================================================================
// DATA STRUCTURE 2 – BST (Binary Search Tree)
// Purpose: stores IPStats ordered by IP string for O(log n)
//          lookup and in-order (alphabetically sorted) traversal.
// ================================================================

struct BSTNode
{
    IPStats  data;
    BSTNode* left;
    BSTNode* right;

    BSTNode(IPStats s) : data(s), left(nullptr), right(nullptr) {}
};

struct IPStatsBST
{
    BSTNode* root;

    IPStatsBST() : root(nullptr) {}

    ~IPStatsBST() { destroyTree(root); }

    void destroyTree(BSTNode* node)
    {
        if (!node) return;
        destroyTree(node->left);
        destroyTree(node->right);
        delete node;
    }

    // Insert or update an IP entry
    void upsert(IPStats stats)
    {
        root = insertNode(root, stats);
    }

    BSTNode* insertNode(BSTNode* node, IPStats stats)
    {
        if (!node) return new BSTNode(stats);
        if (stats.ip < node->data.ip)
            node->left  = insertNode(node->left,  stats);
        else if (stats.ip > node->data.ip)
            node->right = insertNode(node->right, stats);
        else
            node->data = stats;   // update in place
        return node;
    }

    // Find by IP – returns pointer or nullptr
    BSTNode* find(const string& ip) const
    {
        BSTNode* cur = root;
        while (cur)
        {
            if      (ip < cur->data.ip) cur = cur->left;
            else if (ip > cur->data.ip) cur = cur->right;
            else                        return cur;
        }
        return nullptr;
    }

    // In-order traversal: fills a vector sorted by IP string
    void inOrder(BSTNode* node, vector<IPStats>& out) const
    {
        if (!node) return;
        inOrder(node->left,  out);
        out.push_back(node->data);
        inOrder(node->right, out);
    }

    vector<IPStats> getAllSorted() const
    {
        vector<IPStats> out;
        inOrder(root, out);
        return out;
    }

    // Update existing node's stats (used during packet analysis)
    void updateStats(const string& ip,
                     bool synFlag,
                     bool suspPort,
                     bool largePkt,
                     bool susKw)
    {
        BSTNode* node = find(ip);
        if (!node) return;
        node->data.packetCount++;
        if (synFlag)  node->data.synCount++;
        if (suspPort) node->data.suspiciousPortCount++;
        if (largePkt) node->data.largePacketCount++;
        if (susKw)    node->data.keywordCount++;
    }
};

// ================================================================
// DATA STRUCTURE 3 – MAX-HEAP (array-based)
// Purpose: maintains the top-N most-threatening IPs efficiently.
//          After scoring, we heapify all IP stats and pop the top.
// ================================================================

struct IPStatsHeap
{
    vector<IPStats> data;

    // Heapify-up after insertion
    void heapifyUp(int i)
    {
        while (i > 0)
        {
            int parent = (i - 1) / 2;
            if (data[i].threatScore > data[parent].threatScore)
            {
                swap(data[i], data[parent]);
                i = parent;
            }
            else break;
        }
    }

    // Heapify-down after extraction
    void heapifyDown(int i, int n)
    {
        while (true)
        {
            int left  = 2 * i + 1;
            int right = 2 * i + 2;
            int largest = i;

            if (left  < n && data[left].threatScore  > data[largest].threatScore) largest = left;
            if (right < n && data[right].threatScore > data[largest].threatScore) largest = right;

            if (largest != i) { swap(data[i], data[largest]); i = largest; }
            else break;
        }
    }

    void push(IPStats s)
    {
        data.push_back(s);
        heapifyUp((int)data.size() - 1);
    }

    // Return top-N IPs by threat score (destructive – use a copy if needed)
    vector<IPStats> topN(int n)
    {
        vector<IPStats> result;
        vector<IPStats> copy = data;   // save original

        // Convert copy to heap and extract
        IPStatsHeap tmp;
        for (auto& s : copy) tmp.push(s);

        int limit = min(n, (int)tmp.data.size());
        for (int i = 0; i < limit; i++)
        {
            result.push_back(tmp.data[0]);
            swap(tmp.data[0], tmp.data[tmp.data.size() - 1]);
            tmp.data.pop_back();
            tmp.heapifyDown(0, (int)tmp.data.size());
        }
        return result;
    }
};

// ================================================================
// DATA STRUCTURE 4 – PRIORITY QUEUE (alert dispatch)
// Purpose: high-score alerts are dispatched first (urgent alerts
//          surface to the top of the output pipeline).
// ================================================================

struct AlertPQComparator
{
    bool operator()(const Alert& a, const Alert& b)
    {
        return a.score < b.score;   // max-heap by score
    }
};

using AlertPriorityQueue = priority_queue<Alert,
                                          vector<Alert>,
                                          AlertPQComparator>;

// ================================================================
// Input: CSV Reader  →  DATA STRUCTURE 5 – QUEUE
// Purpose: packets are pushed into a queue as they are read;
//          analysis then consumes them FIFO, decoupling I/O from
//          processing (easy to extend to a live-feed or thread).
// ================================================================

bool readPacketsIntoQueue(const string& filePath,
                          queue<Packet>& packetQueue,
                          string& errorMessage)
{
    ifstream inputFile(filePath.c_str());

    if (!inputFile.is_open())
    {
        errorMessage = "Could not open input file.";
        return false;
    }

    string line;
    getline(inputFile, line);   // skip header

    int idCounter = 1;
    while (getline(inputFile, line))
    {
        if (trim(line).empty()) continue;

        vector<string> fields = splitCSVLine(line);
        if ((int)fields.size() < 9) continue;

        Packet p;
        p.id              = idCounter++;
        p.timestamp       = fields[0];
        p.sourceIP        = fields[1];
        p.destinationIP   = fields[2];
        p.sourcePort      = stringToInt(fields[3], 0);
        p.destinationPort = stringToInt(fields[4], 0);
        p.protocol        = fields[5];
        p.packetSize      = stringToInt(fields[6], 0);
        p.flags           = fields[7];
        p.payload         = fields[8];

        packetQueue.push(p);   // QUEUE: enqueue each packet
    }

    inputFile.close();

    if (packetQueue.empty())
    {
        errorMessage = "No valid packets found in CSV file.";
        return false;
    }

    return true;
}

// ================================================================
// IDS Detection Helpers
// ================================================================

bool isSuspiciousPort(int port)
{
    static const int suspPorts[] = {21,22,23,25,53,135,139,445,1433,3306,3389,5900,8080};
    for (int p : suspPorts)
        if (port == p) return true;
    return false;
}

bool hasSuspiciousKeyword(const Packet& packet)
{
    static const string keywords[] =
        {"attack","hack","malware","exploit","shell","password","admin","login"};
    string text = packet.payload + " " + packet.protocol + " " + packet.flags;
    for (const string& kw : keywords)
        if (containsText(text, kw)) return true;
    return false;
}

string getRiskLevel(int score)
{
    if (score >= 100) return "HIGH";
    if (score >= 50)  return "MEDIUM";
    return "LOW";
}

// ================================================================
// Processing: consumes the packet QUEUE, fills the BST and
//             Linked-List, logs events to the STACK.
//
// DATA STRUCTURE 6 – STACK
// Purpose: audit / event log.  Every significant IDS event
//          (new IP discovered, alert raised) is pushed; at the
//          end the stack is drained to write audit_log.txt.
// ================================================================

void analyzePackets(queue<Packet>&    packetQueue,
                    AlertLinkedList&  alertList,
                    IPStatsBST&       ipTree,
                    stack<string>&    auditLog,
                    AlertPriorityQueue& alertPQ,
                    vector<Packet>&   processedPackets)
{
    int alertIdCounter = 1;

    // Consume every packet from the QUEUE
    while (!packetQueue.empty())
    {
        Packet packet = packetQueue.front();   // QUEUE: dequeue
        packetQueue.pop();
        processedPackets.push_back(packet);

        // --- BST: initialise entry for new IPs ---
        if (!ipTree.find(packet.sourceIP))
        {
            IPStats stats;
            stats.ip                 = packet.sourceIP;
            stats.packetCount        = 0;
            stats.synCount           = 0;
            stats.suspiciousPortCount = 0;
            stats.largePacketCount   = 0;
            stats.keywordCount       = 0;
            stats.threatScore        = 0;
            stats.riskLevel          = "LOW";
            ipTree.upsert(stats);

            // STACK: log new IP discovery
            auditLog.push("NEW_IP | " + packet.sourceIP +
                          " | first seen at " + packet.timestamp);
        }

        bool synFlag   = containsText(packet.flags, "SYN");
        bool suspPort  = isSuspiciousPort(packet.destinationPort);
        bool largePkt  = (packet.packetSize > 1400);
        bool susKw     = hasSuspiciousKeyword(packet);

        // BST: update counters
        ipTree.updateStats(packet.sourceIP, synFlag, suspPort, largePkt, susKw);

        // Helper lambda to record an alert
        auto makeAlert = [&](string type, string msg, int score) -> Alert
        {
            Alert a;
            a.id            = alertIdCounter++;
            a.type          = type;
            a.sourceIP      = packet.sourceIP;
            a.destinationIP = packet.destinationIP;
            a.message       = msg;
            a.score         = score;
            a.riskLevel     = getRiskLevel(score);
            return a;
        };

        if (suspPort)
        {
            Alert a = makeAlert("Suspicious Port",
                                "Packet used a commonly attacked destination port.", 60);
            alertList.append(a);             // LINKED LIST: append alert
            alertPQ.push(a);                 // PRIORITY QUEUE: enqueue alert

            // STACK: log event
            auditLog.push("ALERT | Suspicious Port | src=" + packet.sourceIP +
                          " dst=" + packet.destinationIP +
                          " port=" + to_string(packet.destinationPort));
        }

        if (largePkt)
        {
            Alert a = makeAlert("Large Packet",
                                "Packet size is larger than normal expected traffic.", 50);
            alertList.append(a);
            alertPQ.push(a);
            auditLog.push("ALERT | Large Packet | src=" + packet.sourceIP +
                          " size=" + to_string(packet.packetSize));
        }

        if (susKw)
        {
            Alert a = makeAlert("Suspicious Payload",
                                "Payload contains suspicious security-related words.", 100);
            alertList.append(a);
            alertPQ.push(a);
            auditLog.push("ALERT | Suspicious Payload | src=" + packet.sourceIP +
                          " payload snippet=\"" + packet.payload.substr(0,30) + "\"");
        }
    }
}

void calculateScores(IPStatsBST& ipTree)
{
    // Collect all nodes, update scores, re-insert
    vector<IPStats> all = ipTree.getAllSorted();
    for (IPStats& s : all)
    {
        int score = 0;
        score += s.packetCount        * 1;
        score += s.synCount           * 3;
        score += s.suspiciousPortCount * 10;
        score += s.largePacketCount   * 5;
        score += s.keywordCount       * 20;
        s.threatScore = score;
        s.riskLevel   = getRiskLevel(score);
        ipTree.upsert(s);   // BST update in place
    }
}

// ================================================================
// Output Writers
// ================================================================

bool writeAlertsCSV(const string& outputDirectory,
                    const AlertLinkedList& alertList)
{
    string path = joinPath(outputDirectory, "alerts.csv");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    out << "alert_id,type,source_ip,destination_ip,message,risk_level,score\n";

    // Walk the LINKED LIST directly
    AlertNode* cur = alertList.head;
    while (cur)
    {
        const Alert& a = cur->data;
        out << a.id << ","
            << csvEscape(a.type) << ","
            << csvEscape(a.sourceIP) << ","
            << csvEscape(a.destinationIP) << ","
            << csvEscape(a.message) << ","
            << a.riskLevel << ","
            << a.score << "\n";
        cur = cur->next;
    }
    out.close();
    return true;
}

bool writeIPStatsCSV(const string& outputDirectory,
                     const IPStatsBST& ipTree)
{
    string path = joinPath(outputDirectory, "ip_statistics.csv");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    // Get all stats via BST in-order, then sort by threat score desc
    vector<IPStats> sorted = ipTree.getAllSorted();
    sort(sorted.begin(), sorted.end(),
         [](const IPStats& a, const IPStats& b)
         { return a.threatScore > b.threatScore; });

    out << "rank,ip,packets,syn,suspicious_ports,large_packets,keywords,score,risk\n";

    int rank = 1;
    for (const IPStats& s : sorted)
    {
        out << rank++ << ","
            << csvEscape(s.ip) << ","
            << s.packetCount << ","
            << s.synCount << ","
            << s.suspiciousPortCount << ","
            << s.largePacketCount << ","
            << s.keywordCount << ","
            << s.threatScore << ","
            << s.riskLevel << "\n";
    }
    out.close();
    return true;
}

bool writeSearchResultsCSV(const string& outputDirectory,
                           const string& searchIP,
                           const AlertLinkedList& alertList)
{
    string path = joinPath(outputDirectory, "search_results.csv");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    out << "alert_id,type,source_ip,destination_ip,message,risk_level,score\n";

    // LINKED LIST: searchByIP walks the chain
    vector<Alert> matches = alertList.searchByIP(searchIP);
    for (const Alert& a : matches)
    {
        out << a.id << ","
            << csvEscape(a.type) << ","
            << csvEscape(a.sourceIP) << ","
            << csvEscape(a.destinationIP) << ","
            << csvEscape(a.message) << ","
            << a.riskLevel << ","
            << a.score << "\n";
    }
    out.close();

    cout << "Search results for IP " << searchIP
         << ": " << matches.size() << " alert(s) found.\n";
    return true;
}

// Write top-N threats using the MAX-HEAP
bool writeTopThreatsCSV(const string& outputDirectory,
                        IPStatsHeap& heap,
                        int n = 5)
{
    string path = joinPath(outputDirectory, "top_threats.csv");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    out << "rank,ip,score,risk\n";
    vector<IPStats> top = heap.topN(n);
    for (int i = 0; i < (int)top.size(); i++)
    {
        out << (i + 1) << ","
            << csvEscape(top[i].ip) << ","
            << top[i].threatScore << ","
            << top[i].riskLevel << "\n";
    }
    out.close();
    return true;
}

// Drain the STACK to write audit_log.txt (most-recent first)
bool writeAuditLog(const string& outputDirectory,
                   stack<string>& auditLog)
{
    string path = joinPath(outputDirectory, "audit_log.txt");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    out << "IDS Audit Log (most recent event first)\n";
    out << "========================================\n\n";

    while (!auditLog.empty())
    {
        out << auditLog.top() << "\n";   // STACK: pop from top
        auditLog.pop();
    }
    out.close();
    return true;
}

// Write priority-ordered alert dispatch log using PRIORITY QUEUE
bool writePriorityDispatchLog(const string& outputDirectory,
                              AlertPriorityQueue alertPQ)   // copy intentional
{
    string path = joinPath(outputDirectory, "priority_dispatch.csv");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    out << "dispatch_order,alert_id,type,source_ip,score,risk_level\n";

    int order = 1;
    while (!alertPQ.empty())
    {
        const Alert& a = alertPQ.top();   // PRIORITY QUEUE: highest score first
        out << order++ << ","
            << a.id << ","
            << csvEscape(a.type) << ","
            << csvEscape(a.sourceIP) << ","
            << a.score << ","
            << a.riskLevel << "\n";
        alertPQ.pop();
    }
    out.close();
    return true;
}

bool writeSummaryTXT(const string& outputDirectory,
                     int totalPackets,
                     const AlertLinkedList& alertList,
                     const IPStatsBST& ipTree)
{
    string path = joinPath(outputDirectory, "summary.txt");
    ofstream out(path.c_str());
    if (!out.is_open()) return false;

    vector<IPStats> all = ipTree.getAllSorted();

    string topIP    = "N/A";
    int    topScore = 0;
    for (const IPStats& s : all)
    {
        if (s.threatScore > topScore) { topScore = s.threatScore; topIP = s.ip; }
    }

    out << "Simplified IDS Report\n";
    out << "=====================\n\n";
    out << "Total Packets Analyzed: " << totalPackets << "\n";
    out << "Total Source IPs Found: " << all.size() << "\n";
    out << "Total Alerts Generated: " << alertList.size << "\n";
    out << "Most Suspicious IP:     " << topIP << "\n";
    out << "Highest Threat Score:   " << topScore << "\n\n";

    out << "Data Structures Used\n";
    out << "--------------------\n";
    out << "  Queue          : packet ingestion buffer\n";
    out << "  Stack          : audit event log\n";
    out << "  Linked List    : alert chain\n";
    out << "  BST            : IP stats lookup & sorted traversal\n";
    out << "  Max-Heap       : top-threat IP ranking\n";
    out << "  Priority Queue : alert dispatch pipeline\n\n";

    out << "IP Statistics (BST in-order -> sorted by score)\n";
    out << "------------------------------------------------\n";
    for (const IPStats& s : all)
    {
        out << s.ip
            << " | Packets: "          << s.packetCount
            << " | SYN: "              << s.synCount
            << " | Suspicious Ports: " << s.suspiciousPortCount
            << " | Large Packets: "    << s.largePacketCount
            << " | Keywords: "         << s.keywordCount
            << " | Score: "            << s.threatScore
            << " | Risk: "             << s.riskLevel << "\n";
    }

    out.close();
    return true;
}

bool generateSampleCSV(const string& filePath)
{
    ofstream out(filePath.c_str());
    if (!out.is_open()) return false;

    out << "timestamp,source_ip,destination_ip,source_port,destination_port,protocol,packet_size,tcp_flags,payload\n";
    out << "10:00:01,192.168.1.10,192.168.1.1,50100,80,TCP,500,ACK,normal request\n";
    out << "10:00:02,192.168.1.50,192.168.1.1,40100,22,TCP,300,SYN,login attempt\n";
    out << "10:00:03,192.168.1.50,192.168.1.1,40101,3389,TCP,1600,SYN,admin password exploit\n";
    out << "10:00:04,10.0.0.8,192.168.1.100,45000,80,TCP,700,SYN,syn traffic\n";
    out << "10:00:05,10.0.0.8,192.168.1.100,45001,445,TCP,1500,SYN,malware payload\n";
    out.close();
    return true;
}

// ================================================================
// Main Application
// ================================================================

int main(int argc, char* argv[])
{
    string outputDirectory = ".";
    string searchIP        = "";
    string errorMessage    = "";
    bool   success         = true;

    if (argc < 2)
    {
        cout << "Simplified IDS Backend Engine (Data-Structures Edition)\n";
        cout << "Usage:\n";
        cout << "  ids_engine packets.csv\n";
        cout << "  ids_engine packets.csv output_folder\n";
        cout << "  ids_engine packets.csv output_folder --search-ip 192.168.1.50\n";
        cout << "  ids_engine --make-sample sample_packets.csv\n";
        return 0;
    }

    if (string(argv[1]) == "--make-sample")
    {
        if (argc < 3) { cout << "Please provide sample CSV path.\n"; return 1; }
        if (generateSampleCSV(argv[2])) { cout << "Sample CSV generated.\n"; return 0; }
        cout << "Failed to generate sample CSV.\n";
        return 1;
    }

    string inputFilePath = argv[1];
    if (argc >= 3) outputDirectory = argv[2];

    for (int i = 3; i < argc - 1; i++)
        if (string(argv[i]) == "--search-ip")
            searchIP = string(argv[i + 1]);

    // ------------------------------------------------------------------
    // DATA STRUCTURES instantiated here
    // ------------------------------------------------------------------
    queue<Packet>        packetQueue;    // DS1 – QUEUE  (packet buffer)
    stack<string>        auditLog;       // DS2 – STACK  (event audit trail)
    AlertLinkedList      alertList;      // DS3 – LINKED LIST
    IPStatsBST           ipTree;         // DS4 – BST    (IP stats)
    IPStatsHeap          threatHeap;     // DS5 – MAX-HEAP
    AlertPriorityQueue   alertPQ;        // DS6 – PRIORITY QUEUE

    vector<Packet> processedPackets;    // kept for packet count

    // ------------------------------------------------------------------
    // Input: read packets into QUEUE
    // ------------------------------------------------------------------
    if (!readPacketsIntoQueue(inputFilePath, packetQueue, errorMessage))
    {
        cout << "Error: " << errorMessage << "\n";
        return 1;
    }

    auditLog.push("ENGINE_START | input=" + inputFilePath);

    // ------------------------------------------------------------------
    // Processing: drain QUEUE → fill BST + Linked-List + audit STACK
    // ------------------------------------------------------------------
    analyzePackets(packetQueue, alertList, ipTree,
                   auditLog, alertPQ, processedPackets);

    calculateScores(ipTree);

    // Load all scored IPs into the MAX-HEAP
    for (const IPStats& s : ipTree.getAllSorted())
        threatHeap.push(s);

    auditLog.push("ENGINE_DONE | packets=" + to_string(processedPackets.size()) +
                  " alerts=" + to_string(alertList.size));

    // ------------------------------------------------------------------
    // Output (same files as original + two new ones)
    // ------------------------------------------------------------------
    success &= writeAlertsCSV         (outputDirectory, alertList);
    success &= writeIPStatsCSV        (outputDirectory, ipTree);
    success &= writeSummaryTXT        (outputDirectory,
                                       (int)processedPackets.size(),
                                       alertList, ipTree);
    success &= writeTopThreatsCSV     (outputDirectory, threatHeap);       // NEW (heap)
    success &= writePriorityDispatchLog(outputDirectory, alertPQ);          // NEW (PQ)
    success &= writeAuditLog          (outputDirectory, auditLog);          // NEW (stack)

    if (!searchIP.empty())
        success &= writeSearchResultsCSV(outputDirectory, searchIP, alertList);

    if (!success)
    {
        cout << "Analysis completed, but some report files could not be written.\n";
        return 2;
    }

    cout << "IDS Analysis Completed Successfully\n";
    cout << "Packets Analyzed:  " << processedPackets.size() << "\n";
    cout << "Alerts Generated:  " << alertList.size << "\n";
    cout << "Reports written to: " << outputDirectory << "\n";
    cout << "\nOutput files:\n";
    cout << "  alerts.csv            – alert chain (linked list)\n";
    cout << "  ip_statistics.csv     – IP stats (BST sorted)\n";
    cout << "  top_threats.csv       – top 5 IPs (max-heap)\n";
    cout << "  priority_dispatch.csv – alerts by urgency (priority queue)\n";
    cout << "  audit_log.txt         – event trail (stack)\n";
    cout << "  summary.txt           – overall report\n";

    return 0;
}
