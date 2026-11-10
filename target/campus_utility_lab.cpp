#include <sqlite3.h>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <regex>
#include <string>

namespace fs = std::filesystem;
static const char* DB = "target/campus_lab.db";

void init() {
    fs::create_directories("target/documents");
    sqlite3* d = nullptr;
    if (sqlite3_open(DB, &d) != SQLITE_OK) {
        std::cerr << "DB open failed\n";
        if (d) sqlite3_close(d);
        return;
    }
    const char* sql =
        "CREATE TABLE IF NOT EXISTS students(id INTEGER PRIMARY KEY,name TEXT NOT NULL);"
        "INSERT OR IGNORE INTO students VALUES(1,'Alice'),(2,'Bob'),(3,'Charlie');";
    sqlite3_exec(d, sql, nullptr, nullptr, nullptr);
    sqlite3_close(d);
    std::ofstream f("target/documents/welcome.txt", std::ios::app);
    if (f.tellp() == 0) f << "Welcome to Campus Utility.\n";
}

void lookup() {
    std::string id;
    std::cout << "Student ID: ";
    std::getline(std::cin, id);
    sqlite3* d = nullptr;
    sqlite3_stmt* s = nullptr;
    if (sqlite3_open(DB, &d) != SQLITE_OK) {
        std::cerr << "DB open failed\n";
        if (d) sqlite3_close(d);
        return;
    }
#ifdef SECURE_BUILD
    // SAFE: parameterized SQL prevents CWE-89 SQL injection.
    const char* q = "SELECT id,name FROM students WHERE id=?;";
    sqlite3_prepare_v2(d, q, -1, &s, nullptr);
    sqlite3_bind_text(s, 1, id.c_str(), -1, SQLITE_TRANSIENT);
#else
    // VULN 1 / CWE-89: untrusted input is concatenated into SQL.
    std::string q = "SELECT id,name FROM students WHERE id='" + id + "';";
    sqlite3_prepare_v2(d, q.c_str(), -1, &s, nullptr);
#endif
    if (!s) std::cerr << "SQLite error: " << sqlite3_errmsg(d) << '\n';
    else {
        bool found = false;
        while (sqlite3_step(s) == SQLITE_ROW) {
            found = true;
            std::cout << sqlite3_column_int(s, 0) << " | "
                      << reinterpret_cast<const char*>(sqlite3_column_text(s, 1)) << '\n';
        }
        if (!found) std::cout << "No matching student.\n";
    }
    if (s) sqlite3_finalize(s);
    sqlite3_close(d);
}

void connectivity() {
    std::string host;
#ifdef SECURE_BUILD
    std::cout << "IPv4 address: ";
#else
    std::cout << "Host to ping: ";
#endif
    std::getline(std::cin, host);
#ifdef SECURE_BUILD
    // SAFE: strict IPv4 allowlist prevents shell metacharacters reaching the shell.
    static const std::regex ip(
        R"(^(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])(\.(25[0-5]|2[0-4][0-9]|1?[0-9]?[0-9])){3}$)");
    if (!std::regex_match(host, ip)) {
        std::cout << "Rejected: valid IPv4 address required.\n";
        return;
    }
#else
    // VULN 2 / CWE-78: user input is inserted into a shell command.
#endif
    const std::string command = "ping -n 1 " + host;
    std::system(command.c_str());
}

bool inside(const fs::path& base, const fs::path& candidate) {
    const auto rel = candidate.lexically_relative(base);
    if (rel.empty() || rel.is_absolute()) return false;
    for (const auto& part : rel) if (part == "..") return false;
    return true;
}

void document() {
    std::string name;
    std::cout << "Document filename: ";
    std::getline(std::cin, name);
#ifdef SECURE_BUILD
    // SAFE: canonical path must remain inside the documents directory.
    try {
        const auto base = fs::weakly_canonical("target/documents");
        const auto path = fs::weakly_canonical(base / name);
        if (!inside(base, path)) {
            std::cout << "Rejected: path escapes documents directory.\n";
            return;
        }
        std::ifstream f(path);
        if (!f) { std::cout << "Cannot open document.\n"; return; }
        std::string line;
        while (std::getline(f, line)) std::cout << line << '\n';
    } catch (const fs::filesystem_error&) {
        std::cout << "Invalid path.\n";
    }
#else
    // VULN 3 / CWE-22: no containment check; ../ can escape the document folder.
    std::ifstream f(fs::path("target/documents") / name);
    if (!f) { std::cout << "Cannot open document.\n"; return; }
    std::string line;
    while (std::getline(f, line)) std::cout << line << '\n';
#endif
}

void preview() {
    std::string message;
    std::cout << "Message: ";
    std::getline(std::cin, message);
#ifdef SECURE_BUILD
    // SAFE: fixed format string.
    std::printf("%s\n", message.c_str());
#else
    // VULN 4 / CWE-134: attacker-controlled format string.
    std::printf(message.c_str());
    std::printf("\n");
#endif
}

void fee() {
    std::string text;
    std::cout << "Quantity: ";
    std::getline(std::cin, text);
    try {
        const auto n = std::stoull(text);
        if (n > std::numeric_limits<std::uint32_t>::max()) {
            std::cout << "Quantity too large.\n";
            return;
        }
        const std::uint32_t quantity = static_cast<std::uint32_t>(n);
        const std::uint32_t price = 70000;
#ifdef SECURE_BUILD
        // SAFE: multiply in 64 bits, then reject values outside supported range.
        const std::uint64_t total = std::uint64_t(quantity) * price;
        if (total > std::numeric_limits<std::uint32_t>::max()) {
            std::cout << "Rejected: calculation exceeds supported range.\n";
            return;
        }
        std::cout << "Total: " << total << '\n';
#else
        // VULN 5 / CWE-190: 32-bit unsigned multiplication wraps around.
        const std::uint32_t total = quantity * price;
        std::cout << "Total: " << total << '\n';
#endif
    } catch (...) {
        std::cout << "Enter a valid non-negative integer.\n";
    }
}

int main() {
    init();
    for (;;) {
#ifdef SECURE_BUILD
        std::cout << "\n=== Campus Utility (SECURE) ===\n";
#else
        std::cout << "\n=== Campus Utility (5-VULNERABILITY LAB) ===\n";
#endif
        std::cout << "1. Student Lookup\n2. Connectivity Check\n3. Document Viewer\n"
                     "4. Message Preview\n5. Fee Calculator\n0. Exit\nChoice: ";
        std::string c;
        if (!std::getline(std::cin, c)) break;
        if (c == "1") lookup();
        else if (c == "2") connectivity();
        else if (c == "3") document();
        else if (c == "4") preview();
        else if (c == "5") fee();
        else if (c == "0") break;
        else std::cout << "Invalid choice.\n";
    }
}
