#include <iostream>
#include <cstring>
#include <cstdio>
#include <cstdlib>

// --- VULNERABILITY 1: Hardcoded Credentials ---
const char* API_KEY = "AIzaSyD-1234567890abcdefghijklm"; // FAIL: Hardcoded API Key

void bufferOverflow(char* userInput) {
    // --- VULNERABILITY 2: Stack-based Buffer Overflow ---
    // 'strcpy' does not check destination buffer size. If userInput is > 64 chars, it will overflow.
    char buffer[64];
    strcpy(buffer, userInput); 
    std::cout << "Buffer contains: " << buffer << std::endl;
}

void formatStringVulnerability(char* userInput) {
    // --- VULNERABILITY 3: Format String Vulnerability ---
    // User input is passed directly as the format string to 'printf'.
    // An attacker could use "%x" to read stack memory or "%n" to write to memory.
    printf(userInput); 
    printf("\n");
}

void integerOverflow(int userValue) {
    // --- VULNERABILITY 4: Integer Overflow ---
    // If userValue is large, multiplying by 100 can overflow the 32-bit signed integer.
    // This can lead to unexpected small or negative numbers, bypassing size checks.
    int bufferSize = userValue * 100; 
    
    if (bufferSize > 0 && bufferSize < 1000) {
        char* buffer = (char*)malloc(bufferSize);
        std::cout << "Allocated buffer of size: " << bufferSize << std::endl;
        free(buffer);
    } else {
        std::cout << "Invalid buffer size requested." << std::endl;
    }
}

void useAfterFree() {
    // --- VULNERABILITY 5: Use-After-Free ---
    // Memory is allocated, freed, and then accessed again.
    char* ptr = (char*)malloc(100);
    strcpy(ptr, "This is some data.");
    
    std::cout << "Data before free: " << ptr << std::endl;
    free(ptr); // Memory is freed here

    // BAD: Accessing the pointer after it has been freed.
    // The behavior is undefined and could lead to crashes or code execution.
    std::cout << "Data after free (Use-After-Free): " << ptr << std::endl; 
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        std::cout << "Usage: ./vulnerable <string> <int>" << std::endl;
        return 1;
    }

    std::cout << "--- Starting C++ Vulnerability Test ---" << std::endl;

    // Test Buffer Overflow (Pass a string longer than 64 chars to trigger)
    bufferOverflow(argv[1]);

    // Test Format String (Pass "%x %x %x %x" to read stack memory)
    formatStringVulnerability(argv[1]);

    // Test Integer Overflow (Pass a large number like 30000000 to trigger)
    integerOverflow(atoi(argv[2]));

    // Test Use-After-Free
    useAfterFree();

    return 0;
}
