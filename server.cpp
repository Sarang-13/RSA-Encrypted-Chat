#include <iostream>
#include <memory>
#include <thread>
#include <mutex>
#include <map>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <cstring>
#include <nlohmann/json.hpp>
#include "securechat.hpp"
#include "rsa_encryption.hpp"

using json = nlohmann::json;

class ChatServer;

class ClientSession : public std::enable_shared_from_this<ClientSession>
{
public:
    typedef std::shared_ptr<ClientSession> pointer;

    static pointer create(int socket_fd, ChatServer *server);

    int get_socket() const { return socket_fd_; }
    void start();
    void send_message(const std::vector<uint8_t> &data);
    void handle_client_connection();

    const std::string &get_username() const { return username_; }
    const std::string &get_public_key() const { return public_key_; }

private:
    ClientSession(int socket_fd, ChatServer *server)
        : socket_fd_(socket_fd), server_(server), username_(""), public_key_("") {}

    bool read_message(std::vector<uint8_t> &buffer);
    uint32_t read_length_prefix();

    int socket_fd_;
    ChatServer *server_;
    std::string username_;
    std::string public_key_;
};

class ChatServer
{
public:
    ChatServer(int port)
        : port_(port), server_socket_(-1), running_(true)
    {
        std::cout << "Server listening on 0.0.0.0:" << port << std::endl;
    }

    bool initialize()
    {
        // Create server socket
        server_socket_ = socket(AF_INET, SOCK_STREAM, 0);
        if (server_socket_ < 0)
        {
            std::cerr << "Failed to create socket" << std::endl;
            return false;
        }

        // Set socket options
        int opt = 1;
        if (setsockopt(server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
            std::cerr << "Failed to set socket options" << std::endl;
            close(server_socket_);
            return false;
        }

        // Bind socket
        struct sockaddr_in server_addr;
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(port_);

        if (bind(server_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            std::cerr << "Failed to bind socket" << std::endl;
            close(server_socket_);
            return false;
        }

        // Listen for connections
        if (listen(server_socket_, 5) < 0)
        {
            std::cerr << "Failed to listen on socket" << std::endl;
            close(server_socket_);
            return false;
        }

        return true;
    }

    void start_accepting()
    {
        while (running_)
        {
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);

            int client_socket = accept(server_socket_, (struct sockaddr *)&client_addr, &client_addr_len);
            if (client_socket < 0)
            {
                if (running_)
                {
                    std::cerr << "Accept failed" << std::endl;
                }
                continue;
            }

            std::cout << "New connection from " << inet_ntoa(client_addr.sin_addr) << std::endl;

            ClientSession::pointer session = ClientSession::create(client_socket, this);
            std::thread(&ClientSession::handle_client_connection, session).detach();
        }
    }

    void add_client(ClientSession::pointer session)
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.push_back(session);
    }

    void remove_client(ClientSession::pointer session)
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);
        clients_.erase(
            std::remove_if(clients_.begin(), clients_.end(),
                           [session](const ClientSession::pointer &s)
                           { return s == session; }),
            clients_.end());
    }

    void broadcast_system_message(const std::string &message)
    {
        Message msg;
        msg.type = MessageType::SYSTEM;
        msg.data["message"] = message;

        auto frame = Frame::serialize(msg);

        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto &client : clients_)
        {
            try
            {
                client->send_message(frame);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Failed to send system message: " << e.what() << std::endl;
            }
        }
    }

    void broadcast_client_list()
    {
        Message msg;
        msg.type = MessageType::CLIENT_LIST;

        json client_dict;
        {
            std::lock_guard<std::mutex> lock(clients_mutex_);
            for (auto &client : clients_)
            {
                client_dict[client->get_username()] = client->get_public_key();
            }
        }

        msg.data["clients"] = client_dict;
        auto frame = Frame::serialize(msg);

        std::lock_guard<std::mutex> lock(clients_mutex_);
        for (auto &client : clients_)
        {
            try
            {
                client->send_message(frame);
            }
            catch (const std::exception &e)
            {
                std::cerr << "Failed to send client list: " << e.what() << std::endl;
            }
        }
    }

    void forward_chat_message(const std::string &sender,
                              const std::vector<std::string> &recipients,
                              const std::map<std::string, json> &encrypted_messages)
    {
        std::lock_guard<std::mutex> lock(clients_mutex_);

        for (const auto &recipient_name : recipients)
        {
            auto it = std::find_if(clients_.begin(), clients_.end(),
                                   [&recipient_name](const ClientSession::pointer &s)
                                   {
                                       return s->get_username() == recipient_name;
                                   });

            if (it != clients_.end())
            {
                Message msg;
                msg.type = MessageType::CHAT;
                msg.data["sender"] = sender;
                msg.data["message"] = encrypted_messages.at(recipient_name);

                auto frame = Frame::serialize(msg);
                (*it)->send_message(frame);
            }
        }
    }

    void shutdown()
    {
        running_ = false;
        if (server_socket_ >= 0)
        {
            close(server_socket_);
        }
    }

private:
    int port_;
    int server_socket_;
    bool running_;
    std::vector<ClientSession::pointer> clients_;
    std::mutex clients_mutex_;
};

// ClientSession method implementations

ClientSession::pointer ClientSession::create(int socket_fd, ChatServer *server)
{
    return pointer(new ClientSession(socket_fd, server));
}

void ClientSession::start()
{
    // Start the connection handling
}

bool ClientSession::read_message(std::vector<uint8_t> &buffer)
{
    uint8_t temp[8192];
    ssize_t bytes_read = read(socket_fd_, temp, sizeof(temp));

    if (bytes_read <= 0)
    {
        return false;
    }

    buffer.insert(buffer.end(), temp, temp + bytes_read);
    return true;
}

uint32_t ClientSession::read_length_prefix()
{
    uint8_t len_buf[4];
    ssize_t n = read(socket_fd_, len_buf, 4);

    if (n <= 0)
    {
        // n == 0: Connection closed by client
        // n < 0: Socket read error
        throw std::runtime_error("Connection closed");
    }

    if (n != 4)
    {
        throw std::runtime_error("Failed to read length prefix");
    }

    return (len_buf[0] << 24) | (len_buf[1] << 16) | (len_buf[2] << 8) | len_buf[3];
}

void ClientSession::handle_client_connection()
{
    try
    {
        // Read initial connection data (username and public key)
        uint32_t initial_len = read_length_prefix();

        std::vector<uint8_t> data_buffer(initial_len);
        ssize_t n = read(socket_fd_, data_buffer.data(), initial_len);

        if (n != (ssize_t)initial_len)
        {
            throw std::runtime_error("Failed to read initial data");
        }

        std::string json_str(data_buffer.begin(), data_buffer.end());
        json initial_data = json::parse(json_str);

        username_ = initial_data["username"].get<std::string>();
        public_key_ = initial_data["public_key"].get<std::string>();

        std::cout << "Client connected: " << username_ << std::endl;

        // Add to server's client list
        server_->add_client(shared_from_this());

        // Broadcast join message
        server_->broadcast_system_message("** " + username_ + " has joined the chat **");

        // Send updated client list
        server_->broadcast_client_list();

        // Start listening for messages
        while (true)
        {
            uint32_t msg_len = read_length_prefix();

            std::vector<uint8_t> msg_buffer(msg_len);
            ssize_t n = read(socket_fd_, msg_buffer.data(), msg_len);

            if (n != (ssize_t)msg_len)
            {
                throw std::runtime_error("Failed to read message data");
            }

            std::string json_str(msg_buffer.begin(), msg_buffer.end());
            json msg_data = json::parse(json_str);

            if (msg_data["type"] == "chat")
            {
                std::string sender = msg_data["sender"].get<std::string>();
                auto recipients = msg_data["recipients"].get<std::vector<std::string>>();
                auto encrypted_messages = msg_data["encrypted_messages"].get<std::map<std::string, json>>();

                // Forward to each recipient
                server_->forward_chat_message(sender, recipients, encrypted_messages);
            }
        }
    }
    catch (const std::exception &e)
    {
        std::string error_msg = e.what();
        // Don't print error for normal connection close
        if (error_msg != "Connection closed")
        {
            std::cerr << "Error processing client: " << error_msg << std::endl;
        }
    }

    // Cleanup
    close(socket_fd_);
    server_->remove_client(shared_from_this());

    if (!username_.empty())
    {
        std::cout << "Client disconnected: " << username_ << std::endl;
        server_->broadcast_system_message("** " + username_ + " has left the chat **");
        server_->broadcast_client_list();
    }
}

void ClientSession::send_message(const std::vector<uint8_t> &data)
{
    try
    {
        ssize_t n = write(socket_fd_, data.data(), data.size());
        if (n < 0)
        {
            throw std::runtime_error("Failed to send message");
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Failed to send message: " << e.what() << std::endl;
    }
}

int main()
{
    try
    {
        ChatServer server(12345);

        if (!server.initialize())
        {
            return 1;
        }

        std::cout << "Server initialized successfully" << std::endl;
        server.start_accepting();
    }
    catch (std::exception &e)
    {
        std::cerr << "Exception: " << e.what() << std::endl;
    }

    return 0;
}
