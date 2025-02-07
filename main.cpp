// TODO: 
// potential reference https://github.com/alextsao1999/lsp-cpp/blob/master/include/client.h

#include <iostream>
#include <string>
#include <fstream>
#include <unistd.h>
#include <vector>
#include <nlohmann/json.hpp>
#include <signal.h>



class ClangdClient {
private:
    int in_pipe[2];   // clangd reads from this (stdin)
    int out_pipe[2];  // clangd writes to this (stdout)
    pid_t clangd_pid;

public:
    ClangdClient() {
        if (pipe(in_pipe) == -1 || pipe(out_pipe) == -1) {
            perror("pipe");
            exit(1);
        }
        start_clangd();
    }

    ~ClangdClient() {
        close(in_pipe[0]);  close(in_pipe[1]);
        close(out_pipe[0]); close(out_pipe[1]);
        if (clangd_pid > 0) kill(clangd_pid, SIGTERM);
    }

    void start_clangd() {
        clangd_pid = fork();
        if (clangd_pid == 0) {  // Child process (clangd)
            dup2(in_pipe[0], STDIN_FILENO);  // stdin <- in_pipe[0]
            dup2(out_pipe[1], STDOUT_FILENO); // stdout -> out_pipe[1]
            close(in_pipe[1]);  close(out_pipe[0]);
            execlp("clangd", "clangd", "--log=verbose", nullptr);
            perror("execlp");
            exit(1);
        } else if (clangd_pid > 0) {  // Parent process
            close(in_pipe[0]);  // Parent writes to in_pipe[1]
            close(out_pipe[1]); // Parent reads from out_pipe[0]
        } else {
            perror("fork");
            exit(1);
        }
    }

    void send_request(const std::string &json_request) {
        std::string request = "Content-Length: " + std::to_string(json_request.size()) + "\r\n\r\n" + json_request;
        write(in_pipe[1], request.c_str(), request.size());
    }

    std::string read_response() {
        char buffer[4096];
        ssize_t bytes_read = read(out_pipe[0], buffer, sizeof(buffer) - 1);
        if (bytes_read > 0) {
            buffer[bytes_read] = '\0';
            return std::string(buffer);
        }
        return "";
    }

    void send_did_open(const std::string& filename, const std::string& text) {
        nlohmann::json didOpen = {
            {"jsonrpc", "2.0"},
            {"method", "textDocument/didOpen"},
            {"params", {
                {"textDocument", {
                    {"uri", "file://" + filename},
                    {"languageId", "cpp"},
                    {"version", 1},
                    {"text", text}
                }}
            }}
        };
        send_request(didOpen.dump());
    }

    void goto_definition(const std::string& filename, int line, int character) {
        nlohmann::json request = {
            {"jsonrpc", "2.0"},
            {"id", 1},
            {"method", "textDocument/definition"},
            {"params", {
                {"textDocument", {{"uri", "file://" + filename}}},
                {"position", {{"line", line}, {"character", character}}}
            }}
        };
        send_request(request.dump());
    }

    void parse_definition_response(const std::string &response) {
        try {
            auto json_resp = nlohmann::json::parse(response);
            if (json_resp.contains("result") && !json_resp["result"].is_null()) {
                auto def = json_resp["result"][0];  // Assume first result is correct
                std::cout << "Definition found at: " 
                          << def["uri"] << " ("
                          << def["range"]["start"]["line"] << ","
                          << def["range"]["start"]["character"] << ")\n";
            } else {
                std::cout << "No definition found.\n";
            }
        } catch (const std::exception &e) {
            std::cerr << "JSON Parse Error: " << e.what() << std::endl;
        }
    }
};

// Function to read file content into a string
std::string read_file_content(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return "";
    }

    std::string content((std::istreambuf_iterator<char>(file)),
                        std::istreambuf_iterator<char>());
    return content;
}

int main() {
    ClangdClient client;

    // Step 1: Initialize clangd
    std::string init_request = R"({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "processId": null,
            "rootUri": "file:///home/ccn/temp/clangd_test",
            "capabilities": {}
        }
    })";
    
    client.send_request(init_request);
    sleep(1);
    client.read_response();

    std::string file = "/home/ccn/temp/clangd_test/main.cpp";

    // Read the file content and send it to clangd
    std::string file_content = read_file_content(file);
    if (!file_content.empty()) {
        client.send_did_open(file, file_content);
    }
    sleep(1);
    client.read_response();

    // Step 2: Go to definition
    int line = 154;
    int character = 7;
    client.goto_definition(file, line, character);
    sleep(1);
    client.read_response();

    // Step 3: Shutdown clangd properly
    std::string shutdown_request = R"({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "shutdown",
        "params": {}
    })";
    
    client.send_request(shutdown_request);
    sleep(1);
    client.read_response();

    std::string exit_request = R"({
        "jsonrpc": "2.0",
        "method": "exit",
        "params": {}
    })";
    
    client.send_request(exit_request);

    return 0;
}
