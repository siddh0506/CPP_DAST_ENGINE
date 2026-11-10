#include <iostream>
#include <string>
#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <fstream>
#include <limits>
#include <sqlite3.h>

using namespace std;

// --------------------------------------------------
// DATABASE SETUP
// --------------------------------------------------

sqlite3* db = nullptr;

void setupDatabase()
{
    if (sqlite3_open("target/campus_lab.db", &db) != SQLITE_OK)
    {
        cout << "Database error\n";
        return;
    }

    const char* sql =
        "CREATE TABLE IF NOT EXISTS students("
        "id INTEGER PRIMARY KEY,"
        "name TEXT,"
        "department TEXT);"

        "INSERT OR IGNORE INTO students VALUES"
        "(1,'Alice','ECE'),"
        "(2,'Bob','CSE'),"
        "(3,'Charlie','IT');";

    sqlite3_exec(db, sql, nullptr, nullptr, nullptr);
}

// --------------------------------------------------
// 1. SQL INJECTION
// CWE-89
// --------------------------------------------------

void studentLookup()
{
    string id;

    cout << "Enter student ID: ";
    getline(cin, id);

    string query =
        "SELECT * FROM students WHERE id = '" + id + "';";

    cout << "\nExecuting query:\n" << query << "\n";

    sqlite3_exec(
        db,
        query.c_str(),
        [](void*, int argc, char** argv, char** columns) -> int
        {
            for (int i = 0; i < argc; i++)
            {
                cout << columns[i] << ": "
                     << (argv[i] ? argv[i] : "NULL") << " ";
            }

            cout << "\n";
            return 0;
        },
        nullptr,
        nullptr
    );
}

// --------------------------------------------------
// 2. OS COMMAND INJECTION
// CWE-78
// --------------------------------------------------

void connectivityCheck()
{
    string host;

    cout << "Enter hostname or IP: ";
    getline(cin, host);

    string command = "ping -n 1 " + host;

    cout << "Executing connectivity command...\n";

    system(command.c_str());
}

// --------------------------------------------------
// 3. PATH TRAVERSAL
// CWE-22
// --------------------------------------------------

void documentViewer()
{
    string filename;

    cout << "Enter document filename: ";
    getline(cin, filename);

    string path = "lab_files/" + filename;

    ifstream file(path);

    if (!file.is_open())
    {
        cout << "Cannot open document\n";
        return;
    }

    string line;

    while (getline(file, line))
    {
        cout << line << "\n";
    }

    file.close();
}

// --------------------------------------------------
// 4. BUFFER OVERFLOW
// CWE-120
// --------------------------------------------------

void registerStudent()
{
    char name[16];

    string input;

    cout << "Enter student name: ";
    getline(cin, input);

    // INTENTIONALLY VULNERABLE
    strcpy(name, input.c_str());

    cout << "Registered student: " << name << "\n";
}

// --------------------------------------------------
// 5. INTEGER OVERFLOW
// CWE-190
// --------------------------------------------------

void feeCalculator()
{
    unsigned int fee;
    unsigned int quantity;

    cout << "Enter fee per item: ";
    cin >> fee;

    cout << "Enter quantity: ";
    cin >> quantity;

    cin.ignore(numeric_limits<streamsize>::max(), '\n');

    // Unsigned arithmetic can wrap around.
    unsigned int total = fee * quantity;

    cout << "Total fee: " << total << "\n";
}

// --------------------------------------------------
// 6. FORMAT STRING VULNERABILITY
// CWE-134
// --------------------------------------------------

void studentProfile()
{
    string message;

    cout << "Enter profile message: ";
    getline(cin, message);

    // INTENTIONALLY VULNERABLE
    printf(message.c_str());

    printf("\n");
}

// --------------------------------------------------
// 7. USE-AFTER-FREE
// CWE-416
// --------------------------------------------------

void memoryProfile()
{
    char* profile = new char[32];

    strcpy(profile, "Student Profile");

    delete[] profile;

    // INTENTIONALLY VULNERABLE:
    // Accessing memory after it has been released.
    cout << "Profile: " << profile << "\n";
}

// --------------------------------------------------
// MAIN MENU
// --------------------------------------------------

int main()
{
    setupDatabase();

    int choice;

    while (true)
    {
        cout << "\n====================================\n";
        cout << " CAMPUS UTILITY MANAGEMENT SYSTEM\n";
        cout << "====================================\n";

        cout << "1. Student Lookup\n";
        cout << "2. Connectivity Check\n";
        cout << "3. Document Viewer\n";
        cout << "4. Student Registration\n";
        cout << "5. Fee Calculator\n";
        cout << "6. Student Profile Message\n";
        cout << "7. Memory Profile\n";
        cout << "0. Exit\n";

        cout << "\nEnter choice: ";

        if (!(cin >> choice))
            break;

        cin.ignore(numeric_limits<streamsize>::max(), '\n');

        switch (choice)
        {
            case 1:
                studentLookup();
                break;

            case 2:
                connectivityCheck();
                break;

            case 3:
                documentViewer();
                break;

            case 4:
                registerStudent();
                break;

            case 5:
                feeCalculator();
                break;

            case 6:
                studentProfile();
                break;

            case 7:
                memoryProfile();
                break;

            case 0:
                if (db)
                    sqlite3_close(db);

                cout << "Exiting...\n";
                return 0;

            default:
                cout << "Invalid choice\n";
        }
    }

    if (db)
        sqlite3_close(db);

    return 0;
}