#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cstdlib>
#include <unistd.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <termios.h>
#include <pty.h>
#include <poll.h>
#include <fnmatch.h>
#include <sodium.h>
#include "json.hpp" // Download from: https://github.com/nlohmann/json

// Use ordered_json to preserve top-to-bottom insertion order for wildcard priority
using json = nlohmann::ordered_json;

// ============================================================================
// TERMINAL AND FILE UTILITIES
// ============================================================================

// Securely read master password without echoing to the screen
std::string getpass_secure(const char* prompt) {
    int fd = open("/dev/tty", O_RDWR);
    if (fd < 0) {
        throw std::runtime_error("Cannot open /dev/tty. Must be run interactively.");
    }

    termios oldt, newt;
    tcgetattr(fd, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO; // Disable echo
    tcsetattr(fd, TCSANOW, &newt);

    write(fd, prompt, std::string(prompt).length());

    char ch;
    std::string password;
    // Read directly from the terminal, ignoring redirected stdin
    while (read(fd, &ch, 1) == 1 && ch != '\n' && ch != '\r') {
        password += ch;
    }

    tcsetattr(fd, TCSANOW, &oldt); // Restore echo
    write(fd, "\n", 1);
    close(fd);
    return password;
}

std::vector<unsigned char> read_file(const std::string& filename) {
    std::ifstream file(filename, std::ios::binary | std::ios::ate);
    if (!file) throw std::runtime_error("Could not open file for reading: " + filename);
    std::streamsize size = file.tellg();
    file.seekg(0, std::ios::beg);
    std::vector<unsigned char> buffer(size);
    if (!file.read(reinterpret_cast<char*>(buffer.data()), size)) {
        throw std::runtime_error("Failed to read file completely.");
    }
    return buffer;
}

void write_file(const std::string& filename, const std::vector<unsigned char>& data) {
    std::ofstream file(filename, std::ios::binary);
    if (!file) throw std::runtime_error("Could not open file for writing: " + filename);
    file.write(reinterpret_cast<const char*>(data.data()), data.size());
}

void secure_delete_file(const char* filepath) {
    struct stat st;
    if (stat(filepath, &st) == 0) {
        int fd = open(filepath, O_WRONLY);
        if (fd != -1) {
            std::vector<char> zeros(st.st_size, 0);
            write(fd, zeros.data(), zeros.size());
            fsync(fd);
            close(fd);
        }
    }
    unlink(filepath);
}

// ============================================================================
// CRYPTOGRAPHY (LIBSODIUM)
// ============================================================================



std::vector<unsigned char> derive_key(const std::string& password, const std::vector<unsigned char>& salt) {
    std::vector<unsigned char> key(crypto_secretbox_KEYBYTES);
    if (crypto_pwhash(key.data(), key.size(), password.c_str(), password.length(),
                      salt.data(), crypto_pwhash_OPSLIMIT_INTERACTIVE,
                      crypto_pwhash_MEMLIMIT_INTERACTIVE, crypto_pwhash_ALG_DEFAULT) != 0) {
        throw std::runtime_error("Out of memory during key derivation.");
    }
    return key;
}


// Vault encrypter
void encrypt_vault(const std::string& plain_json, const std::string& master_pw, const std::string& out_file) {
    std::vector<unsigned char> salt(crypto_pwhash_SALTBYTES);
    randombytes_buf(salt.data(), salt.size());

    std::vector<unsigned char> key = derive_key(master_pw, salt);

    std::vector<unsigned char> nonce(crypto_secretbox_NONCEBYTES);
    randombytes_buf(nonce.data(), nonce.size());

    std::vector<unsigned char> ciphertext(plain_json.length() + crypto_secretbox_MACBYTES);
    crypto_secretbox_easy(ciphertext.data(), reinterpret_cast<const unsigned char*>(plain_json.data()),
                          plain_json.length(), nonce.data(), key.data());

    sodium_memzero(key.data(), key.size()); // Secure wipe key

    std::vector<unsigned char> payload;
    payload.insert(payload.end(), salt.begin(), salt.end());
    payload.insert(payload.end(), nonce.begin(), nonce.end());
    payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());

    write_file(out_file, payload);
}

// Vault decrypter
std::string decrypt_vault(const std::string& in_file, const std::string& master_pw) {
    std::vector<unsigned char> encrypted_data = read_file(in_file);
    size_t min_length = crypto_pwhash_SALTBYTES + crypto_secretbox_NONCEBYTES + crypto_secretbox_MACBYTES;

    if (encrypted_data.size() < min_length) throw std::runtime_error("File is too small to be a valid vault.");

    auto salt_start = encrypted_data.begin();
    auto nonce_start = salt_start + crypto_pwhash_SALTBYTES;
    auto cipher_start = nonce_start + crypto_secretbox_NONCEBYTES;

    std::vector<unsigned char> salt(salt_start, nonce_start);
    std::vector<unsigned char> nonce(nonce_start, cipher_start);
    std::vector<unsigned char> ciphertext(cipher_start, encrypted_data.end());

    std::vector<unsigned char> key = derive_key(master_pw, salt);
    std::vector<unsigned char> decrypted(ciphertext.size() - crypto_secretbox_MACBYTES);

    if (crypto_secretbox_open_easy(decrypted.data(), ciphertext.data(), ciphertext.size(),
                                   nonce.data(), key.data()) != 0) {
        sodium_memzero(key.data(), key.size());
        throw std::runtime_error("Decryption failed! Wrong password or corrupted file.");
    }

    sodium_memzero(key.data(), key.size()); // Secure wipe key
    return std::string(decrypted.begin(), decrypted.end());
}

// ============================================================================
// VAULT EDITOR
// ============================================================================

void edit_vault(const std::string& vault_file, const std::string& master_pw) {
    std::string plaintext;
    try {
        plaintext = decrypt_vault(vault_file, master_pw);
    } catch (...) {
        std::ifstream f(vault_file);
        if (f.good()) throw; // File exists but failed to decrypt
        // Default JSON template for new vaults
        plaintext = "{\n  \"prompts\": {\n    \"hop1.example.com\": {\n      \"login\": \"Hop1Pass\",\n      \"sudo\": \"Hop1SudoPass\"\n    },\n    \"sub-1-*\": {\n      \"login\": \"Sub1Login\",\n      \"sudo\": \"Sub1Sudo\"\n    },\n    \"default\": {\n      \"login\": \"FallbackLogin\",\n      \"sudo\": \"FallbackSudo\"\n    }\n  }\n}\n";
    }

    char tmp_template[] = "/tmp/pls_XXXXXX";
    int tmp_fd = mkstemp(tmp_template);
    if (tmp_fd == -1) throw std::runtime_error("Failed to create temporary file.");

    fchmod(tmp_fd, 0600); // Make the temporary file with 0600 so prevent other people reading it.

    if (write(tmp_fd, plaintext.data(), plaintext.size()) != plaintext.size()) {
        close(tmp_fd);
        secure_delete_file(tmp_template);
        throw std::runtime_error("Failed to write to temporary file.");
    }
    close(tmp_fd);

    // TODO: Add some method to specify password requirements for vaults???

    // Use the editor set in environment if available.
    const char* editor = getenv("VISUAL");
    if (!editor) editor = getenv("EDITOR");
    if (!editor) editor = "vi";

    pid_t pid = fork();
    if (pid < 0) {
        secure_delete_file(tmp_template);
        throw std::runtime_error("Failed to fork process for text editor.");
    }

    if (pid == 0) {
        execlp(editor, editor, tmp_template, nullptr);
        std::cerr << "Failed to launch editor: " << editor << std::endl;
        exit(1);
    } else {
        int status;
        waitpid(pid, &status, 0);

        if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
            std::vector<unsigned char> new_bytes = read_file(tmp_template);
            std::string new_plaintext(new_bytes.begin(), new_bytes.end());
            encrypt_vault(new_plaintext, master_pw, vault_file);
            std::cout << "Vault successfully updated and encrypted." << std::endl;
        } else {
            std::cerr << "Editor exited with an error. Aborting changes." << std::endl;
        }
        secure_delete_file(tmp_template);
    }
}

// ============================================================================
// PTY EXECUTION AND EXPECT LOGIC
// ============================================================================

void send_to_pty(int fd, const std::string& data) {
    write(fd, data.c_str(), data.length());
    write(fd, "\n", 1);
}

void execute_ssh_session(const json& vault_data, std::vector<const char*> cmd_args) {
    int master_fd;
    pid_t pid = forkpty(&master_fd, nullptr, nullptr, nullptr);

    if (pid < 0) throw std::runtime_error("Failed to fork PTY.");

    if (pid == 0) {
        // Child Process executes the SSH command
        execvp(cmd_args[0], const_cast<char* const*>(cmd_args.data()));
        std::cerr << "Failed to execute SSH command. Is 'ssh' in your PATH?" << std::endl;
        exit(1);
    } else {
        // Parent Process: The half-assed Expect loop
        std::string buffer = "";
        std::string last_trigger = "default";
        char read_buf[256];
        struct pollfd pfd;
        pfd.fd = master_fd;
        pfd.events = POLLIN;

        while (true) {
            int ret = poll(&pfd, 1, -1); // Wait indefinitely for output
            if (ret < 0) break;          // NOTE: Maybe add a timeout function? Relying on ssh timeout seems good enough for now.

            ssize_t bytes_read = read(master_fd, read_buf, sizeof(read_buf) - 1);
            if (bytes_read <= 0) break; // Connection closed

            read_buf[bytes_read] = '\0';
            buffer += read_buf;
            std::cout << read_buf << std::flush; // Echo output to our terminal

            // Check if buffer contains a password prompt
            if (buffer.find("assword") != std::string::npos || buffer.find("assphrase") != std::string::npos) { // hehe ass

                bool password_sent = false;
                bool is_sudo = (buffer.find("[sudo]") != std::string::npos ||
                                buffer.find("password for") != std::string::npos);

                // Iterate through the vault triggers to find a match (in exact file order)
                if (vault_data.contains("prompts")) {

                    // 1. If it's a sudo prompt, try to use the sudo password of the current context
                    if (is_sudo && vault_data["prompts"].contains(last_trigger)) {
                        auto& creds = vault_data["prompts"][last_trigger];
                        if (creds.is_object() && creds.contains("sudo")) {
                            send_to_pty(master_fd, creds["sudo"].get<std::string>());
                            buffer.clear();
                            password_sent = true;
                        }
                    }

                    // 2. Otherwise, treat as a login prompt and find the matching trigger
                    if (!password_sent) {
                        for (auto& [trigger, creds] : vault_data["prompts"].items()) {

                            // Wrap the trigger in wildcards so it matches anywhere in the prompt buffer
                            std::string match_pattern = "*" + trigger + "*";

                            if (trigger == "default" || fnmatch(match_pattern.c_str(), buffer.c_str(), 0) == 0) {
                                std::string pass_to_send;

                                // Handle json credential structures
                                if (creds.is_object() && creds.contains("login")) {
                                    pass_to_send = creds["login"].get<std::string>();
                                }

                                if (!pass_to_send.empty()) {
                                    send_to_pty(master_fd, pass_to_send);
                                    last_trigger = trigger; // Update our context to this host
                                    buffer.clear();
                                    password_sent = true;
                                    break; // Stop at the first successful match
                                }
                            }
                        }
                    }
                }

                if (!password_sent) {
                    std::cerr << "\n[Warning] Prompt detected, but no matching trigger in vault for output: " << buffer << "\n";
                    buffer.clear(); // Clear to prevent infinite loops
                }
            }
        }
        int status;
        waitpid(pid, &status, 0);
    }
}

// ============================================================================
// MAIN CLI
// ============================================================================

// b64 encode helper for scripts
std::string base64_encode(const std::vector<unsigned char>& data) {
    static const char* lookup = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    int val = 0, valb = -6;
    for (unsigned char c : data) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(lookup[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) out.push_back(lookup[((val << 8) >> (valb + 8)) & 0x3F]);
    while (out.size() % 4) out.push_back('=');
    return out;
}

// Help message
void print_usage(const char* prog_name) {
    std::cout << "Usage:\n"
              << "  Edit Vault:    " << prog_name << " -e -v <vault_file>\n"
              << "  Execute SSH:   " << prog_name << " -v <vault_file> [-s <script_file>] [-l <target_list>] -- <ssh arguments...>\n"
              << "\nExamples:\n"
              << "  " << prog_name << " -v secure.vault -- ssh -J user@hop1 target_host -t sudo ls -la\n"
              << "  " << prog_name << " -v secure.vault -s ./script.sh -- ssh -J hop1 target_host\n"
              << "  " << prog_name << " -v secure.vault -l hosts.txt -s ./script.sh -- ssh -J hop1 {TARGET}\n";
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) {
        std::cerr << "Fatal: Libsodium failed to initialize!" << std::endl;
        return 1;
    }

    std::string vault_file = "";
    std::string script_file = "";
    std::string target_list_file = "";
    bool edit_mode = false;
    std::vector<std::string> string_args;

    // Parse arguments
    int opt;
    while ((opt = getopt(argc, argv, "hev:s:l:")) != -1) {
        switch (opt) {
            case 'v': vault_file = optarg; break;
            case 'e': edit_mode = true; break;
            case 's': script_file = optarg; break;
            case 'l': target_list_file = optarg; break;
            case 'h': print_usage(argv[0]); return 0;
            default: print_usage(argv[0]); return 1;
        }
    }

    // Collect remaining arguments for SSH
    for (int i = optind; i < argc; ++i) {
        string_args.push_back(argv[i]);
    }

    if (vault_file.empty()) {
        std::cerr << "Error: Vault file (-v) is required.\n";
        print_usage(argv[0]);
        return 1;
    }

    try {
        std::string master_pw = getpass_secure("Vault Password: ");

        if (edit_mode) {
            edit_vault(vault_file, master_pw);
        } else {
            if (string_args.empty()) {
                std::cerr << "Error: No SSH command provided after '--'.\n";
                return 1;
            }

            // Extract targets from the list file (if provided)
            std::vector<std::string> targets;
            if (!target_list_file.empty()) {
                std::ifstream tfile(target_list_file);
                if (!tfile) {
                    std::cerr << "Error: Could not open target list file: " << target_list_file << "\n";
                    return 1;
                }
                std::string line;
                while (std::getline(tfile, line)) {
                    // Only push non-empty lines
                    if (!line.empty()) targets.push_back(line);
                }
                if (targets.empty()) {
                    std::cerr << "Error: Target list file is empty.\n";
                    return 1;
                }
            } else {
                targets.push_back(""); // Add empty target for a single standard execution
            }

            // If a script is provided, encode it and inject it into the arguments
            if (!script_file.empty()) {
                bool has_script_placeholder = false;
                bool has_t_flag = false;

                // Check if the user manually provided the {SCRIPT} tag or the -t flag
                for (const auto& arg : string_args) {
                    if (arg.find("{SCRIPT}") != std::string::npos) has_script_placeholder = true;
                    if (arg == "-t") has_t_flag = true;
                }

                // Auto-append the default script execution logic if omitted
                if (!has_script_placeholder) {
                    if (!has_t_flag) {
                        string_args.push_back("-t");
                    }
                    string_args.push_back("echo {SCRIPT} | base64 -d | sudo bash");
                }

                std::vector<unsigned char> script_data = read_file(script_file);
                std::string b64_script = base64_encode(script_data);

                for (auto& arg : string_args) {
                    size_t pos;
                    while ((pos = arg.find("{SCRIPT}")) != std::string::npos) {
                        arg.replace(pos, 8, b64_script);
                    }
                }
            }

            // Decrypt and parse JSON ONCE prior to loops
            std::string raw_json = decrypt_vault(vault_file, master_pw);
            json vault_data = json::parse(raw_json);

            // Securely wipe raw JSON string from RAM
            sodium_memzero(raw_json.data(), raw_json.size());

            // Execute the SSH flow iteratively
            for (const auto& target : targets) {
                std::vector<std::string> current_args = string_args;

                // Inject specific host {TARGET} logic
                if (!target.empty()) {
                    std::cout << "\n======================================================\n"
                              << " Executing against target: " << target << "\n"
                              << "======================================================\n"; // Pretty output separator

                    bool replaced = false;
                    for (auto& arg : current_args) {
                        size_t pos;
                        while ((pos = arg.find("{TARGET}")) != std::string::npos) {
                            arg.replace(pos, 8, target);
                            replaced = true;
                        }
                    }

                    if (!replaced) {
                        std::cerr << "Warning: -l was used but {TARGET} placeholder was not found in SSH arguments.\n";
                    }
                }

                // Convert std::string args to const char* pointers for execvp
                std::vector<const char*> ssh_args;
                for (const auto& arg : current_args) {
                    ssh_args.push_back(arg.c_str());
                }
                ssh_args.push_back(nullptr); // Required for execvp

                try {
                    execute_ssh_session(vault_data, ssh_args);
                } catch (const std::exception& e) {
                    std::cerr << "\n[!] Execution failed for target " << target << ": " << e.what() << "\n";
                }
            }
        }

        // Securely wipe master password from RAM
        sodium_memzero(master_pw.data(), master_pw.size());

    } catch (const std::exception& e) {
        std::cerr << "\nError: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}
