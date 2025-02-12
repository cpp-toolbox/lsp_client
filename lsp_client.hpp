#ifndef LSP_CLIENT_HPP
#define LSP_CLIENT_HPP

#include <iostream>
#include <string>
#include <unistd.h>
#include <unordered_set>
#include <vector>
#include <signal.h>
#include <nlohmann/json.hpp>

#include "sbpt_generated_includes.hpp"

using JSON = nlohmann::json;

#ifdef __WIN32
#include <windows.h>
class LSPClientServerCommunicationWindows {
  public:
    HANDLE parent_process_in_write; // lsp server reads from stdin
    HANDLE parent_process_out_read; // lsp server writes to stdout
    PROCESS_INFORMATION lsp_server_process;
    HANDLE parent_process_in_read, parent_process_out_write;

    void start_lsp_server(const std::string &path_to_lsp_server) {
        SECURITY_ATTRIBUTES saAttr;
        saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
        saAttr.bInheritHandle = TRUE;
        saAttr.lpSecurityDescriptor = NULL;

        if (!CreatePipe(&parent_process_out_read, &parent_process_out_write, &saAttr, 0)) {
            throw std::runtime_error("Failed to create stdout pipe");
        }
        if (!CreatePipe(&parent_process_in_read, &parent_process_in_write, &saAttr, 0)) {
            throw std::runtime_error("Failed to create stdin pipe");
        }

        STARTUPINFO si;
        ZeroMemory(&si, sizeof(STARTUPINFO));
        si.cb = sizeof(STARTUPINFO);
        si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
        si.hStdOutput = parent_process_out_write;
        si.hStdInput = parent_process_in_read;
        si.dwFlags |= STARTF_USESTDHANDLES;

        ZeroMemory(&lsp_server_process, sizeof(PROCESS_INFORMATION));
        if (!CreateProcess(NULL, const_cast<char *>(path_to_lsp_server.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si,
                           &lsp_server_process)) {
            throw std::runtime_error("Failed to start LSP server");
        }
    }

    int get_content_length_from_pipe() {
        std::string header;
        char c;
        DWORD bytes_read;
        while (true) {
            if (!ReadFile(parent_process_out_read, &c, 1, &bytes_read, NULL) || bytes_read == 0) {
                throw std::runtime_error("Failed to read content length");
            }
            if (c == '\n')
                break;
            header += c;
        }
        return std::stoi(header.substr(header.find(":") + 1));
    }

    std::string read_from_pipe(int number_of_bytes_to_read) {
        std::vector<char> buffer(number_of_bytes_to_read);
        DWORD bytes_read;
        if (!ReadFile(parent_process_out_read, buffer.data(), number_of_bytes_to_read, &bytes_read, NULL)) {
            throw std::runtime_error("Failed to read from pipe");
        }
        return std::string(buffer.begin(), buffer.begin() + bytes_read);
    }

    JSON get_json_lsp_response() {
        int content_length = get_content_length_from_pipe();
        std::string response = read_from_pipe(content_length);
        return JSON::parse(response);
    }

    void make_json_lsp_request(const JSON &request) {
        std::string request_str =
            "Content-Length: " + std::to_string(request.dump().size()) + "\r\n\r\n" + request.dump();
        DWORD bytes_written;
        if (!WriteFile(parent_process_in_write, request_str.c_str(), request_str.size(), &bytes_written, NULL)) {
            throw std::runtime_error("Failed to write to pipe");
        }
    }

    LSPClientServerCommunicationWindows(const std::string &path_to_lsp_server) { start_lsp_server(path_to_lsp_server); }

    ~LSPClientServerCommunicationWindows() {
        CloseHandle(parent_process_in_write);
        CloseHandle(parent_process_out_read);
        CloseHandle(parent_process_in_read);
        CloseHandle(parent_process_out_write);
        TerminateProcess(lsp_server_process.hProcess, 0);
        CloseHandle(lsp_server_process.hProcess);
        CloseHandle(lsp_server_process.hThread);
    }
};
#else
class LSPClientServerCommunicationLinux {
  public:
    int parent_process_in_pipe[2];  // lsp server reads from stdin
    int parent_process_out_pipe[2]; // lsp server writes to stdout
    pid_t lsp_server_pid;

    void start_lsp_server(const std::string &path_to_lsp_server);
    int get_content_length_from_pipe();
    std::string read_from_pipe(int number_of_bytes_to_read);

    JSON get_json_lsp_response();
    void make_json_lsp_request(const JSON &request);

    LSPClientServerCommunicationLinux(const std::string &path_to_lsp_server);
    ~LSPClientServerCommunicationLinux();
};
#endif

// we only list the methods that we have currently implemented
enum class LSPMethod {
    // https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#initialize
    initialize,
    // https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_definition
    go_to_definition,
};

class LSPClient { // NOTE: only tested to work with LSP 3.17 standard
  private:
    UniqueIDGenerator unique_id_generator;

#ifdef _WIN32
    LSPClientServerCommunicationWindows lsp_communication;
#else
    LSPClientServerCommunicationLinux lsp_communication;
#endif

    bool connection_to_lsp_server_initialized = false;

    std::string root_project_directory;
    std::string language_being_used;

    std::unordered_set<std::string> currently_opened_file_paths_relative_to_project_dir;

    std::map<int, LSPMethod> lsp_request_id_to_lsp_method;
    std::map<int, std::function<void(JSON)>> lsp_request_id_to_callback;

  public:
    // NOTE: make sure that root project directory ends with / fix this later
    LSPClient(const std::string &root_project_directory, const std::string &language_being_used = "cpp",
              const std::string &path_to_lsp_server = "");
    ~LSPClient();

    // todo about to add go to definition function here.
    void process_requests_and_responses();

    void run_callback_associated_with_lsp_request_id(int lsp_request_id, JSON json_lsp_response);

    void did_open(const std::string &file);
    void go_to_definition(const std::string &file, int line, int col, std::function<void(JSON)> callback);

    // old stuff below
    /*void send_request(const std::string &json_request);*/
    /*std::string read_response();*/

    /*void send_did_open(const std::string &filename, const std::string &text);*/
    /*void goto_definition(const std::string &filename, int line, int character,*/
    /*                     const std::function<void(const std::string &, int, int)> &on_definition_found);*/
};

#endif // LSP_CLIENT_HPP
