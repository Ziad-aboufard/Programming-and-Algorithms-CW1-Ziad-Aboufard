#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <ctime>
#include <algorithm>

const int INITIAL_CAPACITY = 10;
const double LOAD_FACTOR_THRESHOLD = 0.5;

// Structure to represent a user with username, password, and next pointer for chaining
struct User {
    std::string username;
    std::string password;
    User* next;

    // Constructor to initialize user with username and password
    User(const std::string& uname, const std::string& pwd) : username(uname), password(pwd), next(nullptr) {}
};

// Class for managing passwords using separate chaining and linear probing
class PasswordManager {
private:
    User** users; // Array of pointers to users
    int capacity; // Capacity of the hash table
    int size; // Current number of elements

    // Hash function for computing hash value of a key (used for separate chaining)
    int hash(const std::string& key) {
        int sum = 0;
        for (char c : key) {
            sum += c;
        }
        return sum % capacity;
    }

    // Encryption function using Caesar cipher
    std::string encrypt(const std::string& password) {
        std::string encryptedPassword = password;
        for (char& c : encryptedPassword) {
            if (isalpha(c)) {
                char base = islower(c) ? 'a' : 'A';
                c = (c - base + 1) % 26 + base; // Shift character by one position
            }
        }
        return encryptedPassword;
    }

    // Decryption function using Caesar cipher
    std::string decrypt(const std::string& encryptedPassword) {
        std::string decryptedPassword = encryptedPassword;
        for (char& c : decryptedPassword) {
            if (isalpha(c)) {
                char base = islower(c) ? 'a' : 'A';
                c = (c - base - 1 + 26) % 26 + base; // Shift character back by one position
            }
        }
        return decryptedPassword;
    }

    // Function to rehash the hash table when load factor exceeds threshold
    void rehash() {
        int newCapacity = capacity * 2; // Double the capacity
        User** newUsers = new User*[newCapacity]; // Create new array with increased capacity
        for (int i = 0; i < newCapacity; ++i) {
            newUsers[i] = nullptr; // Initialize new array with nullptrs
        }
        for (int i = 0; i < capacity; ++i) {
            User* curr = users[i];
            while (curr != nullptr) {
                User* temp = curr->next;
                int index = hash(curr->username) % newCapacity; // Compute new index
                curr->next = newUsers[index]; // Insert into new array
                newUsers[index] = curr;
                curr = temp;
            }
        }
        capacity = newCapacity; // Update capacity
        delete[] users; // Delete old array
        users = newUsers; // Assign new array
    }

    // Function to calculate load factor
    double calculateLoadFactor() {
        return static_cast<double>(size) / capacity;
    }

public:
    // Constructor to initialize hash table with initial capacity
    PasswordManager() : capacity(INITIAL_CAPACITY), size(0) {
        users = new User*[capacity] { nullptr }; // Initialize array of pointers with nullptrs
    }

    // Destructor to deallocate memory
    ~PasswordManager() {
        for (int i = 0; i < capacity; ++i) {
            User* curr = users[i];
            while (curr != nullptr) {
                User* temp = curr->next;
                delete curr; // Delete user
                curr = temp;
            }
        }
        delete[] users; // Delete array
    }

    // Function to add a password to the hash table
    void addPassword(const std::string& username, const std::string& password) {
        std::string encryptedPassword = encrypt(password); // Encrypt password
        int index = hash(username) % capacity; // Compute index
        User* newUser = new User(username, encryptedPassword); // Create new user
        newUser->next = users[index]; // Chain new user
        users[index] = newUser; // Insert user into hash table
        size++; // Increment size
        if (calculateLoadFactor() > LOAD_FACTOR_THRESHOLD) {
            rehash(); // Rehash if load factor exceeds threshold
        }
        std::ofstream userFile(username + ".txt", std::ios::app);
        userFile << encryptedPassword << std::endl; // Store encrypted password in file
        userFile.close();
    }

    // Function to generate and add a password to the hash table
    void generateAndAddPassword(const std::string& username) {
        // Generate a random secure password
        const std::string symbols = "!@#$%^&*()_-+=<>?/[]{},.:;";
        const std::string numbers = "0123456789";
        const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";

        std::string randomPassword;
        srand(time(nullptr)); // Seed the random number generator

        // Add a random symbol
        randomPassword += symbols[rand() % symbols.size()];

        // Add a random number
        randomPassword += numbers[rand() % numbers.size()];

        // Add a random uppercase letter
        randomPassword += uppercase[rand() % uppercase.size()];

        // Fill the rest with lowercase letters
        for (int i = 0; i < 9; ++i) {
            randomPassword += lowercase[rand() % lowercase.size()];
        }

        addPassword(username, randomPassword); // Add generated password
    }

    // Function to retrieve passwords for a given username
    void retrievePasswords(const std::string& username) {
        int index = hash(username) % capacity; // Compute index
        std::cout << "Saved passwords for " << username << ":\n";
        User* curr = users[index]; // Get pointer to first user in chain
        while (curr != nullptr) {
            if (curr->username == username) {
                std::cout << decrypt(curr->password) << std::endl; // Decrypt and print password
            }
            curr = curr->next; // Move to next user in chain
        }
        std::ifstream userFile(username + ".txt");
        std::string storedPassword;
        while (std::getline(userFile, storedPassword)) {
            std::cout << decrypt(storedPassword) << std::endl; // Decrypt and print stored password
        }
        userFile.close();
    }
    
    // Function to login a user with given username and password
    bool loginUser(const std::string& username, const std::string& password) {
        int index = hash(username) % capacity; // Compute index
        User* curr = users[index]; // Get pointer to first user in chain
        while (curr != nullptr) {
            if (curr->username == username && encrypt(password) == curr->password) {
                return true; // Return true if username and password match
            }
                            curr = curr->next; // Move to next user in chain
        }
        return false; // Otherwise, return false
    }
};

// Main function for testing the PasswordManager class
int main() {
    PasswordManager manager;

    // Predefined user list
    const std::pair<std::string, std::string> userList[] = {
        {"Ziad", "123"},
        {"Galal", "123"},
        {"Aboufard", "123"}
    };
    const int userListSize = sizeof(userList) / sizeof(userList[0]);

    // Login process
    std::string username, password;
    bool loggedIn = false;
    while (!loggedIn) {
        std::cout << "Enter username: ";
        std::cin >> username;
        std::cout << "Enter password: ";
        std::cin >> password;

        // Check if username and password match any entry in the predefined user list
        for (int i = 0; i < userListSize; ++i) {
            if (userList[i].first == username && userList[i].second == password) {
                loggedIn = true;
                std::cout << "Logged in successfully!\n";
                break;
            }
        }

        // If login fails, prompt user to try again
        if (!loggedIn) {
            std::cout << "Invalid username or password. Please try again.\n";
        }
    }

    // User options
    std::string choice;
    while (true) {
        std::cout << "Choose an option:\n"
                     "1. Enter new password\n"
                     "2. Generate a password\n"
                     "3. Retrieve saved passwords\n"
                     "4. Logout\n"
                     "Enter your choice: ";
        std::cin >> choice;

        if (choice == "1") {
            std::string newPassword;
            std::cout << "Enter new password: ";
            std::cin >> newPassword;
            manager.addPassword(username, newPassword); // Add new password
            std::cout << "Password added successfully!\n";
        } else if (choice == "2") {
            manager.generateAndAddPassword(username); // Generate and add new password
            std::cout << "Password generated and added successfully!\n";
        } else if (choice == "3") {
            manager.retrievePasswords(username); // Retrieve saved passwords
        } else if (choice == "4") {
            std::cout << "Logged out successfully.\n";
            break; // Logout and exit loop
        } else {
            std::cout << "Invalid choice. Please try again.\n";
        }
    }

    return 0; // Exit program
}
