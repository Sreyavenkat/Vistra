#include <yara.h>
#include <yara/compiler.h>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <map>
#include <cstring>
#include <string>
#include <ctime>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>
#include <unordered_set>
#include <iomanip>
#include <sys/stat.h>
#include <fstream>

#define TYPE_FILE_BATCH 1001

std::vector<std::string> fileResultsJson;

using namespace std;
namespace fs = filesystem;

int total_files_scanned = 0;
int total_quarantined = 0;
int total_deleted = 0;
int total_rule_matches = 0;
int lastProgress = -1;

map<string , int> rule_hit_counts;


/* ---------------- TEST MODE ---------------- */
#define TEST_MODE 1

const string TEST_SCAN_DIR = "/home/kichu/Downloads/FILESS";

/* ---------------- SCAN CONTEXT ---------------- */
struct ScanContext {
    string file_path;
};

/* ---------------- CONFIG ---------------- */
#define DELETE_THRESHOLD 150
#define QUARANTINE_THRESHOLD 80

/* ---------------- GLOBAL SCAN STATE ---------------- */
double total_severity = 0;
string suggested_action = "ignore";
map<string, int> matched_rules;
string final_decision_text = "[OK] CLEAN FILE";
static const unordered_set<string> ignore_ext = {
            ".xml", ".symbols", ".list", ".gz", ".xz"
        };
static const vector<fs::path> skip_paths = {
        "/proc",
        "/sys",
        "/dev",
        "/run",
        "/snap",
        "/tmp",
        "/usr",
        "/boot",
        "/var/log",
        "/var/cache",
        "/home/sreyav/vistra1",
        "/home/kichu/vistra1"
    };


/*----------- PATH SEVERITY MULTIPLIER ----------------*/
double path_severity_multiplier(const fs::path& p) {
    string s = p.string();

    if ((s.rfind("/home",0) == 0) || (s.rfind("/tmp", 0) == 0))
        return 1;      // full weight

    if (s.rfind("/var",0) == 0)
        return 0.3;    // reduce confidence

    if (s.rfind("/usr",0) == 0)
        return 0.1;    // very unlikely

    return 1;
}

/* ---------------- PATH EXCLUSIONS ---------------- */
bool should_skip_path(const fs::path& p) {
    

    fs::path abs_p;
    try {
        abs_p = fs::weakly_canonical(p);
    } catch (...) {
        return false;
    }

    for (const auto& skip : skip_paths) {
        fs::path abs_skip = fs::weakly_canonical(skip);

        // if p == skip OR p is inside skip
        if (abs_p == abs_skip ||
            abs_p.string().compare(0,abs_skip.string().size() + 1,abs_skip.string() + "/") == 0
        ) {
            return true;
        }
    }
    return false;
}



/* ---------------- LOGGING ---------------- */
void log_detection_event(
    //const string& rule_name,
    const string& file_path,
    const string& action,
    int severity
) {
    fs::create_directory("Logs");
    ofstream log("Logs/detections.log", ios::app);
    if (!log.is_open()) return;

    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    log << buf << " | "
        << file_path << " | "
        << action << " | "
        << severity << "\n";
}

/* ---------------- YARA CALLBACK ---------------- */
int yara_callback(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data
) {
    if (message == CALLBACK_MSG_RULE_MATCHING) {

        total_rule_matches++;

        YR_RULE* rule = (YR_RULE*)message_data;
        ScanContext* scanCtx = (ScanContext*)user_data;

        // Track which specific rule matched
        string rule_name = rule->identifier;
        rule_hit_counts[rule_name]++;

        int severity = 0;
        string action = "ignore";

        YR_META* meta;
        yr_rule_metas_foreach(rule, meta) {
            if (strcmp(meta->identifier, "severity") == 0 &&
                meta->type == META_TYPE_INTEGER) {
                severity = meta->integer;
            }
            if (strcmp(meta->identifier, "action") == 0 &&
                meta->type == META_TYPE_STRING) {
                action = meta->string;
            }
        }

        /* path-based severity weighting */
        total_severity += severity * path_severity_multiplier(scanCtx->file_path);
        matched_rules[rule->identifier] = severity;

        if (severity >= QUARANTINE_THRESHOLD && action != "ignore") {
            suggested_action = action;
        }

        

        // cout << "  [+] Rule matched: "
        //      << rule->identifier
        //      << " | severity=" << severity
        //      << " | action=" << action << endl;
    }
    return CALLBACK_CONTINUE;
}


void save_metadata(const fs::path& file, const fs::path& dest) {
    struct stat st;
    stat(file.c_str(), &st);

    ofstream meta(dest.string() + ".meta");
    meta << st.st_mode;
}

/* ---------------- FILE MOVE (SAFE) ---------------- */
fs::path move_file_to_folder(const fs::path& file, const string& folder) {
    cout<<"reached move to folder";
    fs::create_directory(folder);

    fs::path dest = fs::path(folder) /
        (file.stem().string() + "_" +
         to_string(time(nullptr)) +
         file.extension().string());

    try {
        fs::rename(file, dest);
        save_metadata(file, dest);
        // 🔒 Remove execution permissions (owner, group, others)
        chmod(dest.c_str(), S_IRUSR | S_IWUSR);

        cout << "  [→] Moved & quarantined: " << dest << endl;
    } catch (...) {
        cerr << "  [!] Failed to move file\n";
    }

    return dest;
}

void quarantine_file(const fs::path& file) {
    cout << file;
    move_file_to_folder(file, "Quarantine");
}

void delete_file_simulated(const fs::path& file) {
    move_file_to_folder(file, "Deleted");
}

/* ---------------- REPORTING ---------------- */
void write_report(const fs::path& file) {
    fs::create_directory("Reports");
    string report_name = "Reports/" + file.filename().string() + "_report.txt";
    ofstream report(report_name);

    time_t now = time(nullptr);
    char buf[64];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

    report << "##########################################\n";
    report << "YARA SCAN REPORT\n";
    report << "##########################################\n";
    report << "Scan Time:     " << buf << "\n";
    report << "File:          " << file << "\n";
    report << "Decision:      " << final_decision_text << "\n";
    report << "Total Severity:" << total_severity << "\n\n";

    if (!matched_rules.empty()) {
        report << "Matched Rules:\n";
        for (const auto& r : matched_rules) {
            report << "  - " << r.first
                   << " (severity " << r.second << ")\n";
        }
    } else {
        report << "No rules matched.\n";
    }

    report << "##########################################\n";
    report.close();

    cout << "  [✓] Report saved: " << report_name << endl;
}

/* ---------------- LIVE SPINNER ---------------- */
atomic<bool> scanning_done(false);

void spinner() {
    const char* spin_chars = "|/-\\";
    int i = 0;
    while (!scanning_done.load()) {
        cout << "\r[*] Scanning... " << spin_chars[i % 4] << flush;
        i++;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    cout << "\r"; // clear spinner line
}

#include <iostream>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>

int sockfd;

#pragma pack(push, 1)
typedef struct Frame {
    int type;
    float value;
} Frame;
#pragma pack(pop)


#pragma pack(push, 1)
typedef struct Completion {
    int type;
    int totalThreats;
    int quarantine;
    int deletion;
    int safe;
} Completion;
#pragma pack(pop)

void setupSocket() {
    const char* SERVER_IP = "127.0.0.1";
    int PORT = 9000;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) {
        throw runtime_error("Socket creation failed");
    }

    sockaddr_in serverAddr;
    memset(&serverAddr, 0, sizeof(serverAddr));

    serverAddr.sin_family = AF_INET;
    serverAddr.sin_port = htons(PORT);

    if (inet_pton(AF_INET, SERVER_IP, &serverAddr.sin_addr) <= 0) {
        throw runtime_error("Invalid address");
    }

    if (connect(sockfd, (sockaddr*)&serverAddr, sizeof(serverAddr)) < 0) {
        close(sockfd);
        throw runtime_error("Connection failed");
    }

    cout << "[+] Connected to Python server\n";
}


void sendFrame(int type, float value) {
    uint32_t t = htonl(type);

    uint32_t v;
    memcpy(&v, &value, sizeof(float));
    v = htonl(v);

    char buffer[8];
    memcpy(buffer, &t, 4);
    memcpy(buffer + 4, &v, 4);

    send(sockfd, buffer, 8, 0);
}

void sendCompletion(Completion comp) {
    uint32_t t  = htonl(comp.type);
    uint32_t t1 = htonl(comp.totalThreats);
    uint32_t t2 = htonl(comp.quarantine);
    uint32_t t3 = htonl(comp.deletion);
    uint32_t t4 = htonl(comp.safe);

    char buffer[20]; // ✅ FIXED (5 ints)

    memcpy(buffer,      &t,  4);
    memcpy(buffer + 4,  &t1, 4);
    memcpy(buffer + 8,  &t2, 4);
    memcpy(buffer + 12, &t3, 4);
    memcpy(buffer + 16, &t4, 4);

    send(sockfd, buffer, 20, 0);
}

void connectWithRetry() {
    int delay = 2;

    Frame f;

    while (true) {
        try {
            setupSocket();
            break;
        } catch (const exception& e) {
            cout << "[!] " << e.what() << " | Retrying in " << delay << "s\n";
            this_thread::sleep_for(chrono::seconds(delay));
            delay = min(delay * 2, 30);
        }
    }
}

/* ---------------- MAIN ---------------- */
int main() {

    connectWithRetry();

    const string SCAN_DIR = TEST_MODE ? TEST_SCAN_DIR : "/";     
    const string RULE_DIR = "Yara";   
    Completion comFrame;
    yr_initialize();

    /* ----------- RULE COMPILATION ----------- */
    YR_COMPILER* compiler = nullptr;
    yr_compiler_create(&compiler);

    for (const auto& rule : fs::directory_iterator(RULE_DIR)) {
        if (!rule.is_regular_file()) continue;
        FILE* fp = fopen(rule.path().c_str(), "r");
        if (!fp) continue;
        if (yr_compiler_add_file(compiler, fp, nullptr, rule.path().c_str()) != ERROR_SUCCESS) {
            cerr << "[!] Failed to compile rule: " << rule.path() << endl;
            fclose(fp);
            yr_compiler_destroy(compiler);
            yr_finalize();
            return 1;
        }
        fclose(fp);
    }

    YR_RULES* rules = nullptr;
    yr_compiler_get_rules(compiler, &rules);
    yr_compiler_destroy(compiler);

    /* ----------- 1. DYNAMIC PRE-SCAN (No Hardcoding) ----------- */
    int total_eligible_files = 0;
    cout << "[*] Calculating total files for progress bar..." << endl;

    if (TEST_MODE) {
        for (const auto& entry : fs::directory_iterator(SCAN_DIR)) {

            auto ext = entry.path().extension().string();
            if (ignore_ext.count(ext)) continue;

            if (should_skip_path(entry.path())) continue;
            if (!entry.is_regular_file()) continue;

            total_eligible_files++;
        }
    } else {
        for (auto it = fs::recursive_directory_iterator(SCAN_DIR, fs::directory_options::skip_permission_denied);
            it != fs::recursive_directory_iterator(); ++it) {

            const auto& entry = *it;

            auto ext = entry.path().extension().string();
            if (ignore_ext.count(ext)) continue;

            if (should_skip_path(entry.path())) {
                it.disable_recursion_pending();
                continue;
            }

            if (!entry.is_regular_file()) continue;

            total_eligible_files++;
        }
    }
    cout << "[+] Found " << total_eligible_files << " eligible files.\n" << endl;

    /* ----------- 2. RECURSIVE / NON-RECURSIVE SCAN ----------- */
    int files_processed = 0;

    if (TEST_MODE) {

        for (const auto& entry : fs::directory_iterator(SCAN_DIR)) {

            // FILTERS
            auto ext = entry.path().extension().string();
            if (ignore_ext.count(ext)) continue;

            if (should_skip_path(entry.path())) continue;
            if (!entry.is_regular_file()) continue;

            // Counters
            files_processed++;
            total_files_scanned++;

            // Progress
            float progress = (total_eligible_files > 0)
                ? ((float)files_processed / total_eligible_files * 100)
                : 100.0f;

            int current = (int)progress;

            int barWidth = 40;
            string bar = "[";
            int pos = barWidth * (progress / 100.0);

            for (int i = 0; i < barWidth; ++i) {
                if (i < pos) bar += "=";
                else if (i == pos) bar += ">";
                else bar += " ";
            }

            bar += "] " + to_string((int)progress) + "%";

            string current_path = entry.path().string();
            if (current_path.length() > 35) {
                current_path = "..." + current_path.substr(current_path.length() - 32);
            }

            //cout << "\r" << bar << " | Scanning: " << left << setw(35) << current_path << flush;

            // -------- SCAN LOGIC --------
            total_severity = 0;
            suggested_action = "ignore";
            matched_rules.clear();
            final_decision_text = "[OK] CLEAN FILE";

            ScanContext scanCtx;
            scanCtx.file_path = entry.path().string();

            scanning_done = false;
            thread spin_thread(spinner);

            yr_rules_scan_file(rules, entry.path().c_str(), 0, yara_callback, &scanCtx, 0);

            scanning_done = true;
            spin_thread.join();

            // -------- DECISION --------
            // store original details BEFORE modifying file
            std::string original_path = entry.path().string();
            std::string file_name = entry.path().filename().string();

            std::string action = "";
            std::string quarantined_path = "";

            if (total_severity >= DELETE_THRESHOLD) {
                final_decision_text = "[!!!] CONFIRMED RANSOMWARE → DELETE";
                total_deleted++;

                action = "delete";

                // delete file
                try {
                    fs::remove(entry.path());
                } catch (...) {
                    cerr << "Failed to delete file\n";
                }
            }

            else if (total_severity >= QUARANTINE_THRESHOLD || suggested_action == "quarantine") {
                final_decision_text = "[!!] SUSPICIOUS FILE → QUARANTINE";
                total_quarantined++;

                action = "quarantine";

                fs::path dest = move_file_to_folder(entry.path(), "Quarantine");
                quarantined_path = dest.string();  // ✅ IMPORTANT
            }

            // ✅ Store ONLY if needed
            if (action != "") {
                std::string jsonStr = "{";
                jsonStr += "\"file_name\": \"" + file_name + "\",";
                jsonStr += "\"file_path\": \"" + original_path + "\",";
                jsonStr += "\"quarantined_path\": \"" + quarantined_path + "\",";
                jsonStr += "\"action\": \"" + action + "\",";
                jsonStr += "\"severity\": " + std::to_string(total_severity) + ",";
                jsonStr += "\"layer\": 1";
                jsonStr += "}";

            fileResultsJson.push_back(jsonStr);
            }
            
            if (lastProgress != current) {
                lastProgress = current;
                sendFrame(0, current);
            }
            // if(current == 17){
            //     cout << "18 has reached";
            //     break;
            // }
            //write_report(entry.path());
            cout << final_decision_text;
        }

    } else {

        for (auto it = fs::recursive_directory_iterator(SCAN_DIR, fs::directory_options::skip_permission_denied);
            it != fs::recursive_directory_iterator(); ++it) {

            const auto& entry = *it;

            // FILTERS
            auto ext = entry.path().extension().string();
            if (ignore_ext.count(ext)) continue;

            if (should_skip_path(entry.path())) {
                it.disable_recursion_pending();
                continue;
            }

            if (!entry.is_regular_file()) continue;

            // Counters
            files_processed++;
            total_files_scanned++;

            // Progress
            float progress = (total_eligible_files > 0)
                ? ((float)files_processed / total_eligible_files * 100)
                : 100.0f;

            int current = (int)progress;

            int barWidth = 40;
            string bar = "[";
            int pos = barWidth * (progress / 100.0);

            for (int i = 0; i < barWidth; ++i) {
                if (i < pos) bar += "=";
                else if (i == pos) bar += ">";
                else bar += " ";
            }

            bar += "] " + to_string((int)progress) + "%";

            string current_path = entry.path().string();
            if (current_path.length() > 35) {
                current_path = "..." + current_path.substr(current_path.length() - 32);
            }

            cout << "\r" << bar << " | Scanning: "
                << left << setw(35) << current_path << flush;

            // -------- SCAN LOGIC --------
            total_severity = 0;
            suggested_action = "ignore";
            matched_rules.clear();
            final_decision_text = "[OK] CLEAN FILE";

            ScanContext scanCtx;
            scanCtx.file_path = entry.path().string();

            scanning_done = false;
            thread spin_thread(spinner);

            yr_rules_scan_file(rules, entry.path().c_str(), 0, yara_callback, &scanCtx, 0);

            scanning_done = true;
            spin_thread.join();

            // -------- DECISION --------
            if (total_severity >= DELETE_THRESHOLD) {
                final_decision_text = "[!!!] CONFIRMED RANSOMWARE → DELETE";
                total_deleted++;
                log_detection_event(scanCtx.file_path, "Delete", total_severity);
            }
            else if (total_severity >= QUARANTINE_THRESHOLD || suggested_action == "quarantine") {
                final_decision_text = "[!!] SUSPICIOUS FILE → QUARANTINE";
                total_quarantined++;
                quarantine_file(scanCtx.file_path);
                log_detection_event(scanCtx.file_path, "Quarantine", total_severity);
            }

             if (lastProgress != current) {
                lastProgress = current;
                sendFrame(0, current);
            }
            //write_report(entry.path());
        }
    }

    /* ----------- 3. ANALYTICS (No Hardcoding) ----------- */
    string top_rule = "None";
    int max_hits = 0;
    for (const auto& pair : rule_hit_counts) {
        if (pair.second > max_hits) {
            max_hits = pair.second;
            top_rule = pair.first;
        }
    }
    double density = (total_files_scanned > 0) ? (double)total_rule_matches / total_files_scanned : 0;

    /* ----------- FINAL SUMMARY DISPLAY ----------- */
    cout << "\n\n" << string(50, '=') << endl;
    cout << "           DETECTION ANALYTICS SUMMARY          " << endl;
    cout << string(50, '=') << endl;
    cout << " Files Eligible:          " << total_eligible_files << endl;
    cout << " Files Actually Scanned:  " << total_files_scanned << endl;
    cout << " Total YARA Hits:         " << total_rule_matches << endl;
    cout << " Malware Density:         " << fixed << setprecision(4) << density << " hits/file" << endl;
    cout << " Top Threat Signature:    " << top_rule << " (" << max_hits << " hits)" << endl;
    cout << string(50, '-') << endl;
    cout << " Files Quarantined:       " << total_quarantined << endl;
    cout << " Files Deleted:           " << total_deleted << endl;
    cout << string(50, '=') << endl;

    sendFrame(1,100);
    comFrame.type = 999;
    comFrame.deletion = total_deleted;
    comFrame.quarantine = total_quarantined;
    comFrame.safe = total_files_scanned - (total_deleted + total_quarantined);
    comFrame.totalThreats = total_deleted + total_quarantined;
    cout << total_deleted << total_quarantined << comFrame.safe << comFrame.totalThreats;
    sendCompletion(comFrame);

    


    if (!fileResultsJson.empty()) {

        std::string finalJson = "{ \"event\": \"FILES_BATCH\", \"files\": [";

        for (size_t i = 0; i < fileResultsJson.size(); i++) {
            finalJson += fileResultsJson[i];
            if (i != fileResultsJson.size() - 1) {
                finalJson += ",";
            }
        }

        finalJson += "]}";

        uint32_t type = htonl(1001);
        uint32_t length = htonl(finalJson.size());

        send(sockfd, &type, 4, 0);
        send(sockfd, &length, 4, 0);
        send(sockfd, finalJson.c_str(), finalJson.size(), 0);

        std::cout << "📤 Sent FILES_BATCH to agent\n";
    }


    
    yr_rules_destroy(rules);
    yr_finalize();
    cout << "program complete";
    return 0;
}