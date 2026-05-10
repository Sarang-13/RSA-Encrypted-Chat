#include <iostream>
#include <thread>
#include <mutex>
#include <chrono>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <nlohmann/json.hpp>
#include "securechat.hpp"
#include "rsa_encryption.hpp"

using json = nlohmann::json;

class ChatClient
{
public:
    ChatClient(const std::string &username)
        : socket_fd_(-1),
          username_(username),
          connected_(false),
          running_(true)
    {
        // Generate RSA key pair
        std::cout << "Generating RSA keys..." << std::endl;
        auto [priv_key, pub_key] = RSAEncryption::generate_key_pair();
        private_key_ = priv_key;
        public_key_ = pub_key;
        std::cout << "RSA keys generated (2048-bit)" << std::endl;
    }

    bool connect_to_server(const std::string &host, int port)
    {
        try
        {
            std::cout << "Connecting to server..." << std::endl;

            // Create socket
            socket_fd_ = socket(AF_INET, SOCK_STREAM, 0);
            if (socket_fd_ < 0)
            {
                std::cerr << "Failed to create socket" << std::endl;
                return false;
            }

            // Resolve hostname
            struct hostent *server_host = gethostbyname(host.c_str());
            if (server_host == nullptr)
            {
                std::cerr << "Failed to resolve hostname" << std::endl;
                close(socket_fd_);
                return false;
            }

            // Connect to server
            struct sockaddr_in server_addr;
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(port);
            std::memcpy(&server_addr.sin_addr.s_addr, server_host->h_addr, server_host->h_length);

            if (connect(socket_fd_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
            {
                std::cerr << "Connection failed" << std::endl;
                close(socket_fd_);
                return false;
            }

            // Send initial connection data
            json initial_data;
            initial_data["username"] = username_;
            initial_data["public_key"] = public_key_;

            std::string json_str = initial_data.dump();
            std::vector<uint8_t> data(json_str.begin(), json_str.end());

            // Add length prefix
            uint32_t len = data.size();
            std::vector<uint8_t> frame;
            frame.push_back((len >> 24) & 0xFF);
            frame.push_back((len >> 16) & 0xFF);
            frame.push_back((len >> 8) & 0xFF);
            frame.push_back(len & 0xFF);
            frame.insert(frame.end(), data.begin(), data.end());

            ssize_t n = write(socket_fd_, frame.data(), frame.size());
            if (n < 0)
            {
                std::cerr << "Failed to send initial data" << std::endl;
                close(socket_fd_);
                return false;
            }

            connected_ = true;
            std::cout << "Connected to chat server as " << username_ << std::endl;

            // Start receiving messages in a separate thread
            receiver_thread_ = std::thread(&ChatClient::receive_messages, this);

            return true;
        }
        catch (std::exception &e)
        {
            std::cerr << "Connection failed: " << e.what() << std::endl;
            return false;
        }
    }

    void run_interactive()
    {
        std::string command;

        std::cout << "\n=== Secure Chat Client ===" << std::endl;
        std::cout << "Commands:" << std::endl;
        std::cout << "  /users     - List connected users" << std::endl;
        std::cout << "  /msg user message - Send private message" << std::endl;
        std::cout << "  /all message      - Send to everyone" << std::endl;
        std::cout << "  /quit     - Disconnect and exit" << std::endl;
        std::cout << "=======================\n"
                  << std::endl;

        while (running_ && connected_)
        {
            std::cout << "> ";
            std::cout.flush();
            std::getline(std::cin, command);

            // Trim whitespace
            size_t start = command.find_first_not_of(" \t");
            size_t end = command.find_last_not_of(" \t");
            if (start != std::string::npos)
            {
                command = command.substr(start, end - start + 1);
            }
            else
            {
                command = "";
            }

            if (command == "/quit")
            {
                std::cout << "\nDisconnecting..." << std::endl;
                running_ = false;
                connected_ = false;
                break;
            }
            else if (command == "/users")
            {
                print_users();
            }
            else if (command.substr(0, 4) == "/msg" && command.length() > 4)
            {
                size_t space1 = command.find(' ', 5);
                if (space1 != std::string::npos)
                {
                    std::string recipient = command.substr(5, space1 - 5);
                    std::string message = command.substr(space1 + 1);
                    send_message(message, recipient);
                }
            }
            else if (command.substr(0, 4) == "/all" && command.length() > 4)
            {
                std::string message = command.substr(5);
                send_message(message, "Everyone");
            }
            else if (!command.empty())
            {
                send_message(command, "Everyone");
            }
        }
    }

    void disconnect()
    {
        running_ = false;
        connected_ = false;

        try
        {
            if (socket_fd_ >= 0)
            {
                shutdown(socket_fd_, SHUT_RDWR);
                close(socket_fd_);
            }
        }
        catch (...)
        {
        }

        // Wait for receiver thread with timeout
        if (receiver_thread_.joinable())
        {
            // Give the thread 2 seconds to clean up
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            receiver_thread_.join();
        }

        std::cout << "Disconnected." << std::endl;
    }

private:
    void receive_messages()
    {
        std::vector<uint8_t> buffer;

        while (running_)
        {
            try
            {
                std::vector<uint8_t> chunk(8192);
                ssize_t bytes_read = read(socket_fd_, chunk.data(), sizeof(chunk));

                if (bytes_read <= 0)
                    break;

                buffer.insert(buffer.end(), chunk.begin(), chunk.begin() + bytes_read);

                // Process complete frames
                while (buffer.size() >= 4)
                {
                    uint32_t msg_len = (buffer[0] << 24) | (buffer[1] << 16) |
                                       (buffer[2] << 8) | buffer[3];

                    if (buffer.size() < 4 + msg_len)
                        break;

                    std::string json_str(buffer.begin() + 4, buffer.begin() + 4 + msg_len);
                    buffer.erase(buffer.begin(), buffer.begin() + 4 + msg_len);

                    try
                    {
                        json msg_data = json::parse(json_str);
                        process_message(msg_data);
                    }
                    catch (const std::exception &e)
                    {
                        std::cerr << "\n[Error processing message: " << e.what() << "]" << std::endl;
                    }
                }
            }
            catch (const std::exception &e)
            {
                if (running_)
                {
                    std::cerr << "\n[Receive error: " << e.what() << "]" << std::endl;
                }
                break;
            }
        }
        connected_ = false;
    }

    void process_message(const json &msg_data)
    {
        std::string type = msg_data.value("type", "unknown");
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char time_str[20];
        strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&time));

        {
            std::lock_guard<std::mutex> lock(output_mutex_);

            if (type == "system")
            {
                std::string message = msg_data.value("message", "");
                std::cout << "\n[" << time_str << "] " << message << std::endl;
            }
            else if (type == "client_list")
            {
                client_keys_ = msg_data.value("clients", json::object());
            }
            else if (type == "chat")
            {
                std::string sender = msg_data.value("sender", "Unknown");

                if (sender != username_)
                {
                    try
                    {
                        auto encrypted_msg = msg_data.value("message", json::array());
                        std::string decrypted = RSAEncryption::decrypt_message(encrypted_msg, private_key_);
                        std::cout << "\n[" << time_str << "] " << sender << ": " << decrypted << std::endl;
                    }
                    catch (const std::exception &e)
                    {
                        std::cout << "\n[" << time_str << "] " << sender << ": [Decryption error: "
                                  << e.what() << "]" << std::endl;
                    }
                }
            }
        }
    }

    void send_message(const std::string &message, const std::string &recipient)
    {
        try
        {
            json msg_data;
            msg_data["type"] = "chat";
            msg_data["sender"] = username_;
            msg_data["recipients"] = json::array();
            msg_data["encrypted_messages"] = json::object();

            std::vector<std::string> recipients;
            if (recipient == "Everyone")
            {
                for (const auto &[user, key] : client_keys_.items())
                {
                    if (user != username_)
                    {
                        recipients.push_back(user);
                    }
                }
            }
            else
            {
                recipients.push_back(recipient);
            }

            // Add ourselves to see our own message
            if (std::find(recipients.begin(), recipients.end(), username_) == recipients.end())
            {
                recipients.push_back(username_);
            }

            // Encrypt for each recipient
            for (const auto &rcpt : recipients)
            {
                if (client_keys_.contains(rcpt))
                {
                    auto encrypted_msg = RSAEncryption::encrypt_message(message,
                                                                        client_keys_[rcpt].get<std::string>());
                    msg_data["encrypted_messages"][rcpt] = encrypted_msg;
                    msg_data["recipients"].push_back(rcpt);
                }
                else if (rcpt == username_)
                {
                    // Use our own public key for our own messages
                    auto encrypted_msg = RSAEncryption::encrypt_message(message, public_key_);
                    msg_data["encrypted_messages"][rcpt] = encrypted_msg;
                    msg_data["recipients"].push_back(rcpt);
                }
            }

            std::string json_str = msg_data.dump();
            std::vector<uint8_t> data(json_str.begin(), json_str.end());

            // Add length prefix
            uint32_t len = data.size();
            std::vector<uint8_t> frame;
            frame.push_back((len >> 24) & 0xFF);
            frame.push_back((len >> 16) & 0xFF);
            frame.push_back((len >> 8) & 0xFF);
            frame.push_back(len & 0xFF);
            frame.insert(frame.end(), data.begin(), data.end());

            ssize_t n = write(socket_fd_, frame.data(), frame.size());
            if (n < 0)
            {
                throw std::runtime_error("Failed to write to socket");
            }

            auto now = std::chrono::system_clock::now();
            auto time = std::chrono::system_clock::to_time_t(now);
            char time_str[20];
            strftime(time_str, sizeof(time_str), "%H:%M:%S", localtime(&time));

            {
                std::lock_guard<std::mutex> lock(output_mutex_);
                std::cout << "\n[" << time_str << "] You: " << message;
                if (recipient != "Everyone")
                {
                    std::cout << " (to " << recipient << ")";
                }
                std::cout << std::endl;
            }
        }
        catch (const std::exception &e)
        {
            std::lock_guard<std::mutex> lock(output_mutex_);
            std::cerr << "\nSend failed: " << e.what() << std::endl;
        }
    }

    void print_users()
    {
        std::lock_guard<std::mutex> lock(output_mutex_);
        std::cout << "\n=== Connected Users ===" << std::endl;
        for (const auto &[user, key] : client_keys_.items())
        {
            if (user != username_)
            {
                std::cout << "  - " << user << std::endl;
            }
        }
        std::cout << "======================\n"
                  << std::endl;
    }

    int socket_fd_;
    std::string username_;
    std::string private_key_;
    std::string public_key_;
    json client_keys_;
    bool connected_;
    bool running_;
    std::thread receiver_thread_;
    std::mutex output_mutex_;
};

int main(int argc, char *argv[])
{
    std::string username;
    std::string host = "localhost";
    int port = 12345;

    if (argc < 2)
    {
        std::cout << "Usage: " << argv[0] << " <username> [host] [port]" << std::endl;
        std::cout << "Example: " << argv[0] << " alice localhost 12345" << std::endl;
        return 1;
    }

    username = argv[1];
    if (argc > 2)
        host = argv[2];
    if (argc > 3)
        port = std::stoi(argv[3]);

    try
    {
        ChatClient client(username);

        if (client.connect_to_server(host, port))
        {
            client.run_interactive();
        }

        client.disconnect();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
