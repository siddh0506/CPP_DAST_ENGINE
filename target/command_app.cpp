#include <iostream>
#include <cstdlib>
#include <string>

using namespace std;

int main() {
    string input;

    cout << "Enter hostname: ";
    getline(cin, input);

    // INTENTIONALLY VULNERABLE
    string command = "ping -n 1 " + input;

    cout << "Executing command...\n";
    system(command.c_str());

    return 0;
}
