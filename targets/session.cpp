#include <iostream>
#include <sstream>
#include <string>
#include <map>
struct Hold { long long amount, deadline; };
int main() {
    std::map<long long, Hold> holds;
    long long stock = 30, sold = 0, clock = 0;
    std::string line;
    while (std::getline(std::cin, line)) {
        std::istringstream in(line); std::string op, tail; long long id, n;
        in >> op;
        if (op == "RESET" && !(in >> tail)) { stock = 30; sold = 0; clock = 0; holds.clear(); std::cout << "OK\n"; }
        else if (op == "STATUS" && !(in >> tail)) {
            long long held = 0; for (const auto &h : holds) held += h.second.amount;
            std::cout << stock << ' ' << held << ' ' << sold << ' ' << clock << '\n';
        } else if (op == "HOLD" && (in >> id >> n) && !(in >> tail)) {
            if (id < 1 || id > 999 || n < 1 || n > 30) std::cout << "ERR\n";
            else if (holds.count(id)) std::cout << "DUP\n";
            else if (n > stock) std::cout << "SHORT\n";
            else { stock -= n; holds[id] = {n, clock + 4}; std::cout << "OK\n"; }
        } else if ((op == "BUY" || op == "CANCEL") && (in >> id) && !(in >> tail)) {
            if (id < 1 || id > 999) { std::cout << "ERR\n"; continue; }
            auto it = holds.find(id);
            if (it == holds.end()) std::cout << "MISSING\n";
            else { if (op == "BUY") sold += it->second.amount; else stock += it->second.amount;
                holds.erase(it); std::cout << "OK\n"; }
        } else if (op == "TICK" && (in >> n) && !(in >> tail)) {
            if (n < 0 || n > 1000) { std::cout << "ERR\n"; continue; }
            clock += n; long long expired = 0;
            for (auto it = holds.begin(); it != holds.end();) {
                if (it->second.deadline <= clock) { stock += it->second.amount; ++expired; it = holds.erase(it); }
                else ++it;
            }
            std::cout << expired << '\n';
        } else std::cout << "ERR\n";
    }
}
