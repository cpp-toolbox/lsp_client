#ifndef LSP_CLIENT_HPP
#define LSP_CLIENT_HPP

#include <iostream>
#include <string>
#include <unordered_set>
#include <vector>
#include <signal.h>
#include <nlohmann/json.hpp>

#include "sbpt_generated_includes.hpp"

// TODO: extract out text stuff so I don't have to do this.
#include "../../utility/text_buffer/text_buffer.hpp"

using JSON = nlohmann::json;

#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
class LSPClientServerCommunicationWindows {
  public:
    HANDLE parent_process_in_write; // lsp server reads from stdin
    HANDLE parent_process_out_read; // lsp server writes to stdout
    PROCESS_INFORMATION lsp_server_process;
    HANDLE parent_process_in_read, parent_process_out_write;

    // Constructor and Destructor
    LSPClientServerCommunicationWindows(const std::string &path_to_lsp_server);
    ~LSPClientServerCommunicationWindows();

    // Member functions
    void start_lsp_server(const std::string &path_to_lsp_server);
    int get_content_length_from_pipe();
    std::string read_from_pipe(int number_of_bytes_to_read);
    JSON get_json_lsp_response();
    void make_json_lsp_request(const JSON &request);
};
#else
#include <unistd.h>
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

#if defined(_WIN32) || defined(_WIN64)
    LSPClientServerCommunicationWindows lsp_communication;
#else
    LSPClientServerCommunicationLinux lsp_communication;
#endif

    bool connection_to_lsp_server_initialized = false;

    std::string root_project_directory;
    std::string language_being_used;

    // NOTE: based on the LSP spec each document has a version number which
    // increments on each change
    std::unordered_map<std::string, int> document_uri_to_version;

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

    std::string get_full_path(const std::string &file_path) const;
    void make_did_open_request(const std::string &file);
    void make_did_change_request(const std::string &file_path, const TextDiff &text_diff);
    void make_go_to_definition_request(const std::string &file, int line, int col, std::function<void(JSON)> callback);

    // old stuff below
    /*void send_request(const std::string &json_request);*/
    /*std::string read_response();*/

    /*void send_did_open(const std::string &filename, const std::string &text);*/
    /*void goto_definition(const std::string &filename, int line, int character,*/
    /*                     const std::function<void(const std::string &, int, int)> &on_definition_found);*/
};

#endif // LSP_CLIENT_HPP
