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

using namespace std;
namespace fs = filesystem;

int total_files_scanned = 0;
int total_quarantined = 0;
int total_deleted = 0;

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
        YR_RULE* rule = (YR_RULE*)message_data;
        ScanContext* scanCtx = (ScanContext*)user_data;

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

/* ---------------- FILE MOVE (SAFE) ---------------- */
void move_file_to_folder(const fs::path& file, const string& folder) {
    fs::create_directory(folder);

    fs::path dest = fs::path(folder) /
        (file.stem().string() + "_" +
         to_string(time(nullptr)) +
         file.extension().string());

    try {
        fs::rename(file, dest);
        cout << "  [→] Moved to " << folder << endl;
    } catch (...) {
        cerr << "  [!] Failed to move file\n";
    }
}

void quarantine_file(const fs::path& file) {
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

/* ---------------- MAIN ---------------- */
int main() {
    const string SCAN_DIR = "/";      // Entire VM
    const string RULE_DIR = "Yara";   // Your rule directory

    yr_initialize();

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

    /* ----------- RECURSIVE SCAN ----------- */
    for ( auto it = fs::recursive_directory_iterator(
             SCAN_DIR,
             fs::directory_options::skip_permission_denied);
             
             it!= fs::recursive_directory_iterator(); ++it){
                
        const auto& entry = *it;

        total_files_scanned++; //increment total scanned
        
        /* This line is to ignore files with certain extensions( cannot be a ransomware) */
        auto ext = entry.path().extension().string();
        if (ignore_ext.count(ext)) continue;
        
        /* This line is to ignore files and folder which contain garbage data  */
        if(should_skip_path(entry.path())){
            it.disable_recursion_pending();
            continue;
        }
             


        if (!entry.is_regular_file()) continue;

         // Print the exact file path being scanned
        try {
            cout << "[>] Accessing file: " << entry.path() << endl;
        } catch (...) {
            cout << "[!] Could not access file: " << entry.path() << endl;
            continue;
        }

        total_severity = 0;
        suggested_action = "ignore";
        matched_rules.clear();
        final_decision_text = "[OK] CLEAN FILE";

        ScanContext scanCtx;
        scanCtx.file_path = entry.path().string();

        scanning_done = false;
        thread spin_thread(spinner);  // start live spinner

        yr_rules_scan_file(
            rules,
            entry.path().c_str(),
            0,
            yara_callback,
            &scanCtx,
            0
        );

        scanning_done = true;
        spin_thread.join();          // stop spinner

        cout << "[✓] Done scanning: " << entry.path() << endl;

        bool needs_action = false;

        if (total_severity >= DELETE_THRESHOLD) {
            final_decision_text = "[!!!] CONFIRMED RANSOMWARE → DELETE";
            total_deleted++;
            needs_action = true;
            log_detection_event(
            //rule->identifier,
            scanCtx.file_path,
            "Delete",
            total_severity
        );
        }
        else if (total_severity >= QUARANTINE_THRESHOLD ||
                 suggested_action == "quarantine") {
            final_decision_text = "[!!] SUSPICIOUS FILE → QUARANTINE";
            total_quarantined++;
            needs_action = true;
            log_detection_event(
            //rule->identifier,
            scanCtx.file_path,
            "Quarantine",
            total_severity
            );
        }

        cout << final_decision_text << endl;

        write_report(entry.path());

        // if (needs_action) {
        //     if (total_severity >= DELETE_THRESHOLD)
        //         delete_file_simulated(entry.path());
        //     else
        //         quarantine_file(entry.path());
        // }
    }

    /* ----------- FINAL SUMMARY DISPLAY ----------- */
    cout << "\n" << string(45, '=') << endl;
    cout << "           SCAN COMPLETE SUMMARY          " << endl;
    cout << string(45, '=') << endl;
    cout << " Total Files Encountered:  " << total_files_scanned << endl;
    cout << " Files Flagged Suspicious: " << (total_quarantined + total_deleted) << endl;
    cout << "   -> Quarantined:         " << total_quarantined << endl;
    cout << "   -> Deleted :            " << total_deleted << endl;
    cout << string(45, '=') << endl;

    yr_rules_destroy(rules);
    yr_finalize();

    return 0;
}
