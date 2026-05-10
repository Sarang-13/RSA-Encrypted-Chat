#ifndef SECURECHAT_HPP
#define SECURECHAT_HPP

#include <string>
#include <vector>
#include <map>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

// Message types
enum class MessageType {
    SYSTEM,
    CLIENT_LIST,
    CHAT,
    UNKNOWN
};

// Represents a message frame
struct Message {
    MessageType type;
    json data;
    
    // Convert Message to JSON
    json to_json() const {
        json j;
        switch (type) {
            case MessageType::SYSTEM:
                j["type"] = "system";
                break;
            case MessageType::CLIENT_LIST:
                j["type"] = "client_list";
                break;
            case MessageType::CHAT:
                j["type"] = "chat";
                break;
            default:
                j["type"] = "unknown";
        }
        j.update(data);
        return j;
    }
    
    // Create Message from JSON
    static Message from_json(const json& j) {
        Message msg;
        std::string type_str = j["type"].get<std::string>();
        
        if (type_str == "system") msg.type = MessageType::SYSTEM;
        else if (type_str == "client_list") msg.type = MessageType::CLIENT_LIST;
        else if (type_str == "chat") msg.type = MessageType::CHAT;
        else msg.type = MessageType::UNKNOWN;
        
        msg.data = j;
        return msg;
    }
};

// Serialization helpers
struct Frame {
    // Serialize a message to bytes with length prefix (4 bytes big-endian)
    static std::vector<uint8_t> serialize(const Message& msg) {
        std::string json_str = msg.to_json().dump();
        std::vector<uint8_t> data(json_str.begin(), json_str.end());
        
        // Add 4-byte length prefix (big-endian)
        uint32_t len = data.size();
        std::vector<uint8_t> frame;
        frame.push_back((len >> 24) & 0xFF);
        frame.push_back((len >> 16) & 0xFF);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
        frame.insert(frame.end(), data.begin(), data.end());
        
        return frame;
    }
    
    // Deserialize JSON from bytes
    static json parse_json(const std::string& json_str) {
        return json::parse(json_str);
    }
};

#endif // SECURECHAT_HPP
