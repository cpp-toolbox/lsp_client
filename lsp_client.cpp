#include "lsp_client.hpp"
#include <spdlog/spdlog.h>
#include <stdexcept>

#include <fstream>
#include <sstream>
#include <iostream>


#include <string>
#include <sstream>

// TODO: make sure to stop the clangd thread before the program terminates

/**
 * @brief Converts a file path into a local file URI.
 * 
 * @param file_path The absolute file path.
 * @return std::string A local file URI (e.g., file:///C:/path/to/file.txt or file:///home/user/file.txt).
 */
std::string to_file_uri(const std::string& file_path) {
    std::ostringstream uri;
    uri << "file://";

    // On Windows, file paths start with a drive letter (C:\), so we need to handle it properly.
#if defined(_WIN32) || defined(_WIN64)
    uri << "/";
    for (char ch : file_path) {
        if (ch == '\\') {
            uri << '/'; // Convert backslashes to forward slashes
        } else {
            uri << ch;
        }
    }
#else
    uri << file_path; // UNIX-based systems already use forward slashes
#endif

    return uri.str();
}


#if defined(_WIN32) || defined(_WIN64)
LSPClientServerCommunicationWindows::LSPClientServerCommunicationWindows(const std::string &path_to_lsp_server) {
    start_lsp_server(path_to_lsp_server);
}

LSPClientServerCommunicationWindows::~LSPClientServerCommunicationWindows() {
    CloseHandle(parent_process_in_write);
    CloseHandle(parent_process_out_read);
    CloseHandle(parent_process_in_read);
    CloseHandle(parent_process_out_write);
    TerminateProcess(lsp_server_process.hProcess, 0);
    CloseHandle(lsp_server_process.hProcess);
    CloseHandle(lsp_server_process.hThread);
}

void LSPClientServerCommunicationWindows::start_lsp_server(const std::string &path_to_lsp_server) {
std::cout << "start lsp server" << std::endl;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;

std::cout << "before creating pipes" << std::endl;

    if (!CreatePipe(&parent_process_out_read, &parent_process_out_write, &saAttr, 0)) {
        throw std::runtime_error("Failed to create stdout pipe");
    }
    if (!CreatePipe(&parent_process_in_read, &parent_process_in_write, &saAttr, 0)) {
        throw std::runtime_error("Failed to create stdin pipe");
    }

std::cout << "after creating pipes" << std::endl;

    STARTUPINFO si;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    si.cb = sizeof(STARTUPINFO);
    si.hStdError = GetStdHandle(STD_ERROR_HANDLE);
    si.hStdOutput = parent_process_out_write;
    si.hStdInput = parent_process_in_read;
    si.dwFlags |= STARTF_USESTDHANDLES;

std::cout << "before creating process" << std::endl;

    ZeroMemory(&lsp_server_process, sizeof(PROCESS_INFORMATION));
    if (!CreateProcess(NULL, const_cast<char *>(path_to_lsp_server.c_str()), NULL, NULL, TRUE, 0, NULL, NULL, &si,
                       &lsp_server_process)) {
        throw std::runtime_error("Failed to start LSP server");
    }

std::cout << "after creating process" << std::endl;
}

int LSPClientServerCommunicationWindows::get_content_length_from_pipe() {
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

std::string LSPClientServerCommunicationWindows::read_from_pipe(int number_of_bytes_to_read) {
    std::vector<char> buffer(number_of_bytes_to_read);
    DWORD bytes_read;
    if (!ReadFile(parent_process_out_read, buffer.data(), number_of_bytes_to_read, &bytes_read, NULL)) {
        throw std::runtime_error("Failed to read from pipe");
    }
    return std::string(buffer.begin(), buffer.begin() + bytes_read);
}

JSON LSPClientServerCommunicationWindows::get_json_lsp_response() {
std::cout << "start get json lsp response" << std::endl;
    // TODO: we have to figure out why the +2 is required...
    int content_length = get_content_length_from_pipe() + 2;

    if (content_length <= 0) {
        std::cerr << "[ERROR] Invalid Content-Length: " << content_length << std::endl;
        throw std::runtime_error("Invalid Content-Length received.");
    }

    std::string response = read_from_pipe(content_length);

    try {
        JSON json_response = JSON::parse(response);
        return json_response;
    } catch (const std::exception& e) {
        std::cerr << "[ERROR] JSON parsing error: " << e.what() << std::endl;
        std::cerr << "[ERROR] Raw JSON response: " << response << std::endl;
        throw;
    }
}

void LSPClientServerCommunicationWindows::make_json_lsp_request(const JSON &request) {
	// TODO: was debugging why the thing crashes when the lsp client starts
	std::cout << "about to make json lsp request" << std::endl;
    std::string request_str =
        "Content-Length: " + std::to_string(request.dump().size()) + "\r\n\r\n" + request.dump();
    DWORD bytes_written;
    if (!WriteFile(parent_process_in_write, request_str.c_str(), request_str.size(), &bytes_written, NULL)) {
        throw std::runtime_error("Failed to write to pipe");
    }
}

#else
LSPClientServerCommunicationLinux::LSPClientServerCommunicationLinux(const std::string &path_to_lsp_server) {
    // create two pipes for communication, note that
    // you always write to pipe[1] and read from pipe[0]
    // so later on you'll see we "turn one of them around"
    if (pipe(parent_process_in_pipe) == -1 || pipe(parent_process_out_pipe) == -1) {
        throw std::runtime_error("Failed to create pipes");
    }
    start_lsp_server(path_to_lsp_server);
}

LSPClientServerCommunicationLinux::~LSPClientServerCommunicationLinux() {
    close(parent_process_in_pipe[0]);
    close(parent_process_in_pipe[1]);
    close(parent_process_out_pipe[0]);
    close(parent_process_out_pipe[1]);

    if (lsp_server_pid > 0) {
        if (kill(lsp_server_pid, SIGTERM) == -1) {
            spdlog::error("Failed to terminate clangd process");
        }
    }
}

void LSPClientServerCommunicationLinux::start_lsp_server(const std::string &path_to_lsp_server) {
    // NOTE this code only works on linux for now.

    // when you create a pipe it has two ends, here we create two pipes
    // we will then modify the pipes to make them an in and out pipe
    //
    //     PARENT PROCESS ------fork---------->  CHILD PROCESS
    //           1>>>>>>>>>>>>>>in_pipe>>>>>>>>>>>>>>>0
    //           0<<<<<<<<<<<<<out_pipe<<<<<<<<<<<<<<<1
    //
    lsp_server_pid = fork();

    bool code_is_running_in_child_process = lsp_server_pid == 0;
    bool code_is_running_in_parent_process = lsp_server_pid > 0;

    if (code_is_running_in_child_process) {

        // here we make standard in and stanard out come from the pipes, this essentially makes the connection
        // TODO: why do we need to redirect? is it so we can read the messages?
        bool standard_in_redirected_to_read_from_in_pipe_0 = dup2(parent_process_in_pipe[0], STDIN_FILENO) != -1;
        bool standard_out_redirected_to_read_from_in_pipe_1 = dup2(parent_process_out_pipe[1], STDOUT_FILENO) != -1;

        if (not(standard_in_redirected_to_read_from_in_pipe_0 and standard_out_redirected_to_read_from_in_pipe_1)) {
            perror("Failed to redirect pipes");
            exit(1);
        }

        // we don't need access to the other end of the pipe
        close(parent_process_in_pipe[1]);
        close(parent_process_out_pipe[0]);

        if (path_to_lsp_server == "") {
            execlp("clangd", "clangd", "--log=verbose", nullptr);
        } else {
        }

        perror("execlp failed");
        exit(1);
    } else if (code_is_running_in_parent_process) {
        close(parent_process_in_pipe[0]);  // parent writes to in_pipe[1]
        close(parent_process_out_pipe[1]); // parent reads from out_pipe[0]
    } else {
        perror("Failed to fork process");
        throw std::runtime_error("Failed to fork process");
    }
}

/**
 * @brief Reads the "Content-Length" header from the pipe and returns its value.
 *
 * This function reads from a pipe until a newline is encountered, searches for
 * the "Content-Length" header, and converts the corresponding value to an integer.
 *
 * Note that this function is only valid because the only thing that will be ever written to the pipe
 * will be LSP responses, which all start with content length making this function safe
 *
 * @param pipe_fd The file descriptor of the pipe to read from.
 * @return int The value of the "Content-Length" header, or -1 if there is an error or if the header is not found.
 */
int LSPClientServerCommunicationLinux::get_content_length_from_pipe() {
    char header_buffer[255]; // Buffer to store the header data
    int bytes_read = 0;

    // read character by character until newline is reached
    // the while loop termination condidition should never be reached
    // as the message should be a LSP response which starts with
    // Content-Length: XYZ, and the number shouldn't be that large?
    while (bytes_read < sizeof(header_buffer) - 1) {
        // read will block until there is data in the pipe
        // thus this could be bad?
        if (read(parent_process_out_pipe[0], &header_buffer[bytes_read], 1) <= 0) {
            return -1; // Read error or EOF
        }
        if (header_buffer[bytes_read] == '\n') {
            header_buffer[bytes_read] = '\0'; // Null-terminate the line
            break;
        }
        bytes_read++;
    }

    const char *content_length_header = strstr(header_buffer, "Content-Length: ");
    if (!content_length_header) {
        std::cout << "Invalid or missing 'Content-Length' header" << std::endl;
        return -1;
    }

    // Move the pointer to the start of the number value
    // using 16 because that's the length of 'Content-Length: `
    const char *content_length_value = content_length_header + 16;

    // Skip any leading spaces before the number, shouldn't exist anyway.
    while (*content_length_value == ' ') {
        content_length_value++;
    }

    // Convert the value from string to integer
    return atoi(content_length_value);
}

// WARN: this needs to be run in a thread because it is blocking!
std::string LSPClientServerCommunicationLinux::read_from_pipe(int number_of_bytes_to_read) {
    std::string what_was_read;
    what_was_read.resize(number_of_bytes_to_read);
    // WARN: blocking!
    read(parent_process_out_pipe[0], &what_was_read[0], number_of_bytes_to_read);
    return what_was_read;
}

// WARN: this needs to be run in a thread because it is blocking!
JSON LSPClientServerCommunicationLinux::get_json_lsp_response() {
    int content_length = get_content_length_from_pipe();
    // TODO: why do I have to do +2 here?
    std::string potential_json_lsp_response = read_from_pipe(content_length + 2);

    JSON lsp_response;
    try {
        lsp_response = nlohmann::json::parse(potential_json_lsp_response);
    } catch (std::exception &e) {
        std::cerr << "Read error: " << e.what() << "\n";
        std::cout << lsp_response << std::endl;
    }
    return lsp_response;
}

void LSPClientServerCommunicationLinux::make_json_lsp_request(const JSON &request) {
    std::string content = request.dump();
    std::string header = "Content-Length: " + std::to_string(content.length()) + "\r\n\r\n" + content;

    if (write(parent_process_in_pipe[1], header.c_str(), header.length()) == -1) {
        std::cout << "Failed to send request to clangd" << std::endl;
    }
}
#endif

LSPClient::LSPClient(const std::string &root_project_directory, const std::string &language_being_used,
                     const std::string &path_to_lsp_server)
    : lsp_communication(path_to_lsp_server), language_being_used(language_being_used),
      root_project_directory(root_project_directory) {
	      std::cout << "constructor" << std::endl;
    int request_id = UniqueIDGenerator::generate();

    lsp_request_id_to_lsp_method[request_id] = LSPMethod::initialize;
    lsp_request_id_to_callback[request_id] = [&](JSON lsp_response) {
        connection_to_lsp_server_initialized = true;
        std::cout << "initialization complete" << std::endl;
    };
    // clang-format off
    JSON initialize_request = {
        {"jsonrpc", "2.0"}, 
        {"id", request_id}, 
        {"method", "initialize"}, 
        {"params", {
            {"processId", "null"},
            {"rootUri", to_file_uri(root_project_directory)},
            {"capabilities", {}}
        }}
    };
    // clang-format on
    std::cout << "before initialization request" << std::endl;
    lsp_communication.make_json_lsp_request(initialize_request);
}

LSPClient::~LSPClient() {}

void LSPClient::run_callback_associated_with_lsp_request_id(int lsp_request_id, JSON json_lsp_response) {
std::cout << "running callback start" << std::endl;
    auto it = lsp_request_id_to_callback.find(lsp_request_id);
    bool callback_exists_for_request_id = it != lsp_request_id_to_callback.end();
    if (callback_exists_for_request_id) {
        auto callback_associated_with_request_id = it->second;
        callback_associated_with_request_id(json_lsp_response);

        // Erase the callback and the associated LSP method
        lsp_request_id_to_callback.erase(it);
        lsp_request_id_to_lsp_method.erase(lsp_request_id);
    } else {
        std::cout << "Request ID not found: " << lsp_request_id << "\n";
    }
std::cout << "running callback end" << std::endl;
}

// WARN: this needs to be run in a thread because it is blocking!
void LSPClient::process_requests_and_responses() {

std::cout << "running process_requests_and_responses start" << std::endl;
    JSON lsp_response = lsp_communication.get_json_lsp_response();
std::cout << "after lsp response" << std::endl;
    bool has_id = lsp_response.count("id");

    if (has_id) {
        bool is_request = lsp_response.contains("method");
        bool is_response = lsp_response.contains("result");
        bool is_error = lsp_response.contains("error");
        if (is_request) {
        } else if (is_response) {
            // NOTE: the response id matches the
            // request id, this is important
            int response_id = lsp_response["id"];
            run_callback_associated_with_lsp_request_id(response_id, lsp_response);
        } else if (is_error) {
        }
    }
std::cout << "running process_requests_and_responses end" << std::endl;
}

void LSPClient::did_open(const std::string &file_path) {

    std::string full_path = file_path;
    // the forward slash indicates absolute path on linux
    // the C indicates absolute path on windows

#if defined(_WIN32) || defined(_WIN64)
    if (file_path[0] != 'C') { 
        full_path = root_project_directory + file_path;
    }
#else
    if (file_path[0] != '/') { 
        full_path = root_project_directory + file_path;
    }
#endif

    std::ifstream file_stream(full_path);
    if (!file_stream) {
        std::cerr << "Failed to read file: " << full_path << std::endl;
        return;
    }

    std::cout << "working on did open for path: " << full_path << std::endl;

    std::stringstream buffer;
    buffer << file_stream.rdbuf(); // Read entire file into buffer
    std::string file_contents = buffer.str();

    JSON did_open_request = {{"jsonrpc", "2.0"},
                             {"method", "textDocument/didOpen"},
                             {"params",
                              {{"textDocument",
                                {
					// TODO: Was just looking here and adding in a foward slash
                                    {"uri", to_file_uri(full_path)},
                                    {"languageId", language_being_used}, // Change if needed
                                    {"version", 1},
                                    {"text", file_contents} // Send actual file contents
                                }}}}};

    std::cout << did_open_request << std::endl;

    lsp_communication.make_json_lsp_request(did_open_request);
}

void LSPClient::go_to_definition(const std::string &file_path, int line, int col, std::function<void(JSON)> callback) {
    int request_id = UniqueIDGenerator::generate();

    lsp_request_id_to_lsp_method[request_id] = LSPMethod::go_to_definition;
    lsp_request_id_to_callback[request_id] = callback;

    // Determine if file_path is absolute
    std::string full_path = file_path;
    if (file_path.empty() || file_path[0] != '/') { // Not absolute, prepend root dir
        full_path = root_project_directory + file_path;
    }

    // clang-format off
    JSON go_to_definition_request = {
        {"jsonrpc", "2.0"},
        {"id", request_id},
        {"method", "textDocument/definition"},
        {"params", {
            {"textDocument", {{"uri", to_file_uri(full_path)}}},
            {"position", {{"line", line}, {"character", col}}}
        }}
    };
    // clang-format on

    lsp_communication.make_json_lsp_request(go_to_definition_request);
}

/*void send_did_open(const std::string &filename, const std::string &text) {*/
/*    nlohmann::json didOpen = {*/
/*        {"jsonrpc", "2.0"},*/
/*        {"method", "textDocument/didOpen"},*/
/*        {"params",*/
/*         {{"textDocument", {{"uri", "file://" + filename}, {"languageId", "cpp"}, {"version", 1}, {"text",
 * text}}}}}};*/
/*    send_request(didOpen.dump());*/
/*}*/
/**/
/*void goto_definition(const std::string &filename, int line, int character,*/
/*                                const std::function<void(const std::string &, int, int)> &on_definition_found) {*/
/**/
/*    nlohmann::json request = {{"jsonrpc", "2.0"},*/
/*                              {"id", 1},*/
/*                              {"method", "textDocument/definition"},*/
/*                              {"params",*/
/*                               {{"textDocument", {{"uri", "file://" + filename}}},*/
/*                                {"position", {{"line", line}, {"character", character}}}}}};*/
/**/
/*    send_request(request.dump()); // Send the request*/
/**/
/*    std::string response = read_response(); // Read the LSP server's response*/
/*    spdlog::debug("Raw LSP Response: {}", response);*/
/**/
/*    try {*/
/*        auto json_resp = nlohmann::json::parse(response);*/
/*        if (json_resp.contains("result") && !json_resp["result"].is_null()) {*/
/*            auto def = json_resp["result"][0]; // Assume first result is correct*/
/*            std::string uri = def["uri"];*/
/*            int def_line = def["range"]["start"]["line"];*/
/*            int def_character = def["range"]["start"]["character"];*/
/**/
/*            on_definition_found(uri, def_line, def_character);*/
/*        } else {*/
/*            spdlog::info("No definition found for the given position");*/
/*        }*/
/*    } catch (const std::exception &e) {*/
/*        spdlog::error("Failed to parse JSON response: {}", e.what());*/
/*    }*/
/*}*/
