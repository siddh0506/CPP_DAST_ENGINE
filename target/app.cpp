#include <iostream>
#include <string>
#include <sqlite3.h>

using namespace std;

// Function to display database query results
int displayResults(
    void* data,
    int columns,
    char** values,
    char** names
)
{
    for (int i = 0; i < columns; i++)
    {
        cout << (values[i] ? values[i] : "NULL");

        if (i < columns - 1)
        {
            cout << " | ";
        }
    }

    cout << endl;

    return 0;
}

int main()
{
    sqlite3* db = nullptr;

    // Connect to SQLite database
    int rc = sqlite3_open("target/lab.db", &db);

    if (rc != SQLITE_OK)
    {
        cerr << "Database connection failed: "
             << sqlite3_errmsg(db) << endl;

        sqlite3_close(db);

        return 1;
    }

    // Create users table
    const char* createTable =
        "CREATE TABLE IF NOT EXISTS users ("
        "id INTEGER PRIMARY KEY, "
        "username TEXT, "
        "role TEXT"
        ");";

    char* errorMessage = nullptr;

    rc = sqlite3_exec(
        db,
        createTable,
        nullptr,
        nullptr,
        &errorMessage
    );

    if (rc != SQLITE_OK)
    {
        cerr << "Table creation failed: "
             << errorMessage << endl;

        sqlite3_free(errorMessage);
        sqlite3_close(db);

        return 1;
    }

    // Insert dummy records
    const char* insertUsers =
        "INSERT OR IGNORE INTO users VALUES "
        "(1, 'alice', 'user'),"
        "(2, 'bob', 'admin'),"
        "(3, 'charlie', 'user');";

    rc = sqlite3_exec(
        db,
        insertUsers,
        nullptr,
        nullptr,
        &errorMessage
    );

    if (rc != SQLITE_OK)
    {
        cerr << "Data insertion failed: "
             << errorMessage << endl;

        sqlite3_free(errorMessage);
        sqlite3_close(db);

        return 1;
    }

    // Receive user input
    string userInput;

    cout << "Enter User ID: ";
    getline(cin, userInput);

    /*
       INTENTIONALLY VULNERABLE SQL QUERY

       User input is directly concatenated
       into the SQL query without parameterization.
    */

    string query =
        "SELECT id, username FROM users WHERE id = '"
        + userInput + "';";

    cout << "\nExecuting database query...\n";

    // Execute SQL query
    rc = sqlite3_exec(
        db,
        query.c_str(),
        displayResults,
        nullptr,
        &errorMessage
    );

    if (rc != SQLITE_OK)
    {
        cerr << "SQL ERROR: "
             << errorMessage << endl;

        sqlite3_free(errorMessage);
        sqlite3_close(db);

        return 2;
    }

    sqlite3_close(db);

    return 0;
}  