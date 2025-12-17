#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "shell32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

// 强制使用正确的入口点
#pragma comment(linker, "/ENTRY:mainCRTStartup")
#pragma comment(linker, "/SUBSYSTEM:WINDOWS")

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "winhttp.lib")

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winhttp.h>
#include <commctrl.h>
#include <windowsx.h>  // 包含Button_GetCheck和Button_SetCheck宏定义
#include <shellapi.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <thread>
#include <atomic>
#include <chrono>
#include <iostream>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>
#include <queue>
#include <unordered_map>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <wincrypt.h>
#include <iphlpapi.h>
#include <intrin.h> 

// JSON 简单实现 (轻量级，避免外部依赖)
#include <map>

// 资源ID定义
#define IDC_PROCESS_LIST    1001
#define IDC_REFRESH_BUTTON  1002
#define IDC_START_BUTTON    1003
#define IDC_STOP_BUTTON     1004
#define IDC_STATUS_TEXT     1005
#define IDC_LOG_TEXT        1006
#define IDC_APPLY_CONFIG_BUTTON  1026

// 治疗配置控件ID
#define IDC_CONFIG_GROUP        1010
#define IDC_NORMAL_CHECK        1011
#define IDC_NORMAL_HP_EDIT      1012
#define IDC_NORMAL_KEY_EDIT     1013
#define IDC_ENHANCED_CHECK      1014
#define IDC_ENHANCED_HP_EDIT    1015
#define IDC_ENHANCED_KEY_EDIT   1016
#define IDC_EMERGENCY1_CHECK    1017
#define IDC_EMERGENCY1_HP_EDIT  1018
#define IDC_EMERGENCY1_KEY_EDIT 1019
#define IDC_EMERGENCY2_CHECK    1020
#define IDC_EMERGENCY2_HP_EDIT  1021
#define IDC_EMERGENCY2_KEY_EDIT 1022
#define IDC_SP_CHECK            1023
#define IDC_SP_PERCENT_EDIT     1024
#define IDC_SP_KEY_EDIT         1025

#define IDC_MACHINE_ID_EDIT     2001
#define IDC_AUTH_CODE_EDIT      2002
#define IDC_COPY_MACHINE_ID     2003
#define IDD_AUTH_DIALOG         2000

#define IDC_SKILL_CHECK            1027
#define IDC_SKILL_HP_EDIT          1028
#define IDC_SKILL_KEY_EDIT         1029
#define IDC_SKILL_COOLDOWN_EDIT    1030

// 前向声明
class ConfigurableHealBotUI;
extern ConfigurableHealBotUI* g_ui_instance;

// 函数声明（定义将在类定义之后）
void LogMessage(const std::string& message);


//远端认证json解析

class SimpleJSONParser {
public:
    static bool GetBoolValue(const std::string& json, const std::string& key) {
        size_t pos = json.find("\"" + key + "\"");
        if (pos == std::string::npos) return false;

        size_t value_start = json.find(":", pos);
        if (value_start == std::string::npos) return false;

        size_t true_pos = json.find("true", value_start);
        size_t false_pos = json.find("false", value_start);

        if (true_pos != std::string::npos &&
            (false_pos == std::string::npos || true_pos < false_pos)) {
            return true;
        }
        return false;
    }

    static std::string GetStringValue(const std::string& json, const std::string& key) {
        size_t key_pos = json.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return "";

        size_t colon_pos = json.find(":", key_pos);
        if (colon_pos == std::string::npos) return "";

        size_t quote_start = json.find("\"", colon_pos);
        if (quote_start == std::string::npos) return "";

        size_t quote_end = json.find("\"", quote_start + 1);
        if (quote_end == std::string::npos) return "";

        return json.substr(quote_start + 1, quote_end - quote_start - 1);
    }

    static int GetIntValue(const std::string& json, const std::string& key) {
        size_t key_pos = json.find("\"" + key + "\"");
        if (key_pos == std::string::npos) return 0;

        size_t colon_pos = json.find(":", key_pos);
        if (colon_pos == std::string::npos) return 0;

        size_t num_start = colon_pos + 1;
        while (num_start < json.length() &&
            (json[num_start] == ' ' || json[num_start] == '\t')) {
            num_start++;
        }

        size_t num_end = num_start;
        while (num_end < json.length() &&
            (isdigit(json[num_end]) || json[num_end] == '-')) {
            num_end++;
        }

        if (num_start >= num_end) return 0;

        std::string num_str = json.substr(num_start, num_end - num_start);
        return std::atoi(num_str.c_str());
    }
};

// 简化的自定义加密算法类
class CustomCrypto {
private:
    static constexpr const char* MAGIC_SALT = "HB2024_SECURE_KEY";
    static constexpr uint32_t MAGIC_CONST1 = 0x9E3779B9;
    static constexpr uint32_t MAGIC_CONST2 = 0x5A827999;

public:
    // 简化的加密函数
    static std::string Encrypt(const std::string& plaintext, const std::string& key) {
        std::string result;
        std::string full_key = key + MAGIC_SALT;

        for (size_t i = 0; i < plaintext.length(); i++) {
            uint8_t ch = static_cast<uint8_t>(plaintext[i]);

            // 第一层：简单字节替换
            ch = (ch + 73) & 0xFF;

            // 第二层：密钥异或
            ch ^= static_cast<uint8_t>(full_key[i % full_key.length()]);

            // 第三层：位置相关混合
            uint32_t pos_mix = (i * MAGIC_CONST1) ^ MAGIC_CONST2;
            ch ^= static_cast<uint8_t>(pos_mix & 0xFF);

            // 第四层：简单位移
            uint8_t shift = (i % 5) + 1;
            ch = ((ch << shift) | (ch >> (8 - shift))) & 0xFF;

            result.push_back(static_cast<char>(ch));
        }

        return ToHexString(result);
    }

    // 简化的解密函数
    static std::string Decrypt(const std::string& ciphertext, const std::string& key) {
        std::string decoded = FromHexString(ciphertext);
        if (decoded.empty()) return "";

        std::string result;
        std::string full_key = key + MAGIC_SALT;

        for (size_t i = 0; i < decoded.length(); i++) {
            uint8_t ch = static_cast<uint8_t>(decoded[i]);

            // 逆向第四层：位移还原
            uint8_t shift = (i % 5) + 1;
            ch = ((ch >> shift) | (ch << (8 - shift))) & 0xFF;

            // 逆向第三层：位置相关混合
            uint32_t pos_mix = (i * MAGIC_CONST1) ^ MAGIC_CONST2;
            ch ^= static_cast<uint8_t>(pos_mix & 0xFF);

            // 逆向第二层：密钥异或
            ch ^= static_cast<uint8_t>(full_key[i % full_key.length()]);

            // 逆向第一层：字节替换还原
            ch = (ch - 73) & 0xFF;

            result.push_back(static_cast<char>(ch));
        }

        return result;
    }

private:
    // 转换为十六进制字符串
    static std::string ToHexString(const std::string& input) {
        std::stringstream ss;
        for (unsigned char c : input) {
            ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c);
        }
        return ss.str();
    }

    // 从十六进制字符串转换回来
    static std::string FromHexString(const std::string& hex) {
        if (hex.length() % 2 != 0) return "";

        std::string result;
        for (size_t i = 0; i < hex.length(); i += 2) {
            std::string byte_str = hex.substr(i, 2);
            char byte = static_cast<char>(strtol(byte_str.c_str(), nullptr, 16));
            result.push_back(byte);
        }
        return result;
    }
};




class PeriodicAuthVerifier {
private:
    std::atomic<bool> running_{ false };
    std::thread verification_thread_;

    std::string machine_id_;
    std::string auth_code_;

    // 统计数据
    std::atomic<uint64_t> uptime_seconds_{ 0 };
    std::atomic<uint64_t> keys_sent_{ 0 };

    // 失败计数
    std::atomic<int> fail_count_{ 0 };
    static constexpr int MAX_FAIL_COUNT = 3;

public:
    bool Start(const std::string& machine_id, const std::string& auth_code) {
        if (running_.load()) return true;

        machine_id_ = machine_id;
        auth_code_ = auth_code;

        //HeartbeatResult initial_result = PerformHeartbeat();
        //if (!initial_result.valid) {
        //    std::this_thread::sleep_for(std::chrono::seconds(60));
        //    LogMessage("❌ 初次心跳验证失败");
        //    return false;
        //}

        running_.store(true);
        uptime_seconds_.store(0);

        // ⭐ 启动后台验证线程（完全独立运行）
        verification_thread_ = std::thread([this]() {
            VerificationLoop();
            });

        LogMessage("✅ 后台验证已启动（完全静默模式）");
        return true;

    }

    void Stop() {
        if (!running_.load()) return;
        running_.store(false);

        if (verification_thread_.joinable()) {
            verification_thread_.join();
        }
    }

    // ⭐ 可选：统计按键（不影响性能）
    inline void IncrementKeysSent() {
        keys_sent_.fetch_add(1, std::memory_order_relaxed);
    }

private:
    void VerificationLoop() {
        auto start_time = std::chrono::steady_clock::now();
        int next_check_seconds = 300; // 默认5分钟
        Sleep(30000);
        while (running_.load()) {
            // 更新运行时间
            auto now = std::chrono::steady_clock::now();
            uptime_seconds_.store(
                std::chrono::duration_cast<std::chrono::seconds>(now - start_time).count(),
                std::memory_order_relaxed
            );

            // 等待下次检查时间（分段睡眠，便于快速退出）
            for (int i = 0; i < next_check_seconds && running_.load(); i++) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }

            if (!running_.load()) break;
            
            // ⭐ 执行心跳验证（完全在后台，不阻塞任何逻辑）
            HeartbeatResult result = PerformHeartbeat();

            if (!result.valid) {
                fail_count_++;
                //LogMessage("⚠️ 后台验证失败 (" + std::to_string(fail_count_.load()) +
                    //"/" + std::to_string(MAX_FAIL_COUNT) + ")");

                if (fail_count_ >= MAX_FAIL_COUNT) {
                    LogMessage("❌ 授权验证连续失败，程序将在10秒后退出");
                    LogMessage("可能原因：授权被撤销、网络问题、服务器维护");

                    // 延迟退出，让用户看到提示
                    std::this_thread::sleep_for(std::chrono::seconds(10));

                    // ⭐ 直接退出整个程序
                    ExitProcess(-1);
                }
            }
            else {
                // 验证成功，重置失败计数
                fail_count_.store(0);

                // 根据服务器指令处理
                if (result.action == "exit") {
                    //LogMessage("⚠️ 服务器要求退出程序");
                    LogMessage("原因：授权已被管理员撤销");
                    std::this_thread::sleep_for(std::chrono::seconds(5));
                    ExitProcess(-1);

                }
                else if (result.action == "pause") {
                    LogMessage("⚠️ 服务器检测到异常行为，暂停功能");
                    LogMessage("如有疑问请联系管理员");
                    std::this_thread::sleep_for(std::chrono::seconds(30));
                    ExitProcess(-1);

                }
                else if (result.action == "continue") {
                    // 正常继续
                    next_check_seconds = result.next_check_seconds;

                    // 添加随机抖动 ±20%
                    int jitter = (rand() % 40 - 20) * next_check_seconds / 100;
                    next_check_seconds = std::max(60, next_check_seconds + jitter);

                    //LogMessage("✅ 后台验证通过，下次检查: " +
                        //std::to_string(next_check_seconds) + "秒后");
                }
            }
        }

        LogMessage("后台验证线程已退出");
    }

    struct HeartbeatResult {
        bool valid;
        std::string action;
        int next_check_seconds;
    };

    HeartbeatResult PerformHeartbeat() {
        HeartbeatResult result = { false, "exit", 300 };

        HINTERNET hSession = WinHttpOpen(
            L"HealBot/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) return result;

        HINTERNET hConnect = WinHttpConnect(
            hSession,
            L"heal-bo-service-ftrskdkhwk.cn-hangzhou.fcapp.run",
            INTERNET_DEFAULT_HTTPS_PORT, 0);

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return result;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            L"/heartbeat",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }

        // 构建请求体
        std::stringstream ss;
        ss << "{"
            << "\"machine_code\":\"" << machine_id_ << "\","
            << "\"auth_code\":\"" << auth_code_ << "\","
            << "\"uptime\":" << uptime_seconds_.load() << ","
            << "\"keys_sent\":" << keys_sent_.load()
            << "}";
        std::string json_body = ss.str();

        std::wstring headers = L"Content-Type: application/json";

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            -1,
            (LPVOID)json_body.c_str(),
            static_cast<DWORD>(json_body.length()),
            static_cast<DWORD>(json_body.length()),
            0);

        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return result;
        }

        // 读取响应
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char* pszOutBuffer = new char[8192];

        do {
            dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                if (WinHttpReadData(hRequest, pszOutBuffer, dwSize, &dwDownloaded)) {
                    response.append(pszOutBuffer, dwDownloaded);
                }
            }
        } while (dwSize > 0);

        delete[] pszOutBuffer;

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // 解析响应
        result.valid = SimpleJSONParser::GetBoolValue(response, "valid");
        result.action = SimpleJSONParser::GetStringValue(response, "action");
        result.next_check_seconds = SimpleJSONParser::GetIntValue(response, "next_check");

        if (result.next_check_seconds <= 0) {
            result.next_check_seconds = 300;
        }

        return result;
    }
};

class SoftwareAuth {
private:
    static constexpr const char* SECRET_PASSWORD = "HEALBOT_2024_MASTER_SECRET";
    static constexpr const char* REGISTRY_KEY = "SOFTWARE\\HealBot";
    static constexpr const char* AUTH_VALUE = "LicenseKey";

    // 新增：最后验证时间缓存（可选，用于减少频繁网络请求）
    static constexpr const char* LAST_VERIFY_TIME = "LastVerifyTime";
    static constexpr int VERIFY_INTERVAL_SECONDS = 1800; // 30分钟重新验证一次
    // 对话框数据结构
    struct AuthDialogData {
        std::string machine_id;
        bool result;
        HWND hDlg;
        HWND hMachineEdit;
        HWND hAuthEdit;
    };


private:
    // 验证配置
    static constexpr const char* VERIFY_API_HOST = "heal-bo-service-ftrskdkhwk.cn-hangzhou.fcapp.run";
    static constexpr const wchar_t* VERIFY_API_PATH = L"/verify";
    static constexpr const wchar_t* UPDATE_API_PATH = L"/update-status";

    static uint32_t ComputeChallengeResponse(uint32_t challenge, const std::string& machine_code) {
        uint32_t hash = challenge;

        // 混合机器码
        for (char c : machine_code) {
            hash = ((hash << 5) + hash) + static_cast<uint8_t>(c);  // hash * 33 + c
        }

        // 魔法变换
        hash ^= 0xDEADBEEF;
        hash = (hash >> 16) | (hash << 16);  // 交换高低16位

        return hash;
    }

    static bool UpdateRemoteAuthStatus(const std::string& machine_code, bool is_authorized) {
        HINTERNET hSession = WinHttpOpen(
            L"HealBot/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(
            hSession,
            L"heal-bo-service-ftrskdkhwk.cn-hangzhou.fcapp.run", 
            INTERNET_DEFAULT_HTTPS_PORT, 0);

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",                         
            L"/update-status",          
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // ✅ 构建 JSON 请求体
        std::string json_body = "{\"machine_code\":\"" + machine_code +
            "\",\"is_authorized\":" +
            (is_authorized ? "true" : "false") + "}";

        // ✅ 设置 Content-Type 为 JSON
        std::wstring headers = L"Content-Type: application/json";

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            -1,
            (LPVOID)json_body.c_str(),
            static_cast<DWORD>(json_body.length()),
            static_cast<DWORD>(json_body.length()),
            0);

        if (bResults) {
            bResults = WinHttpReceiveResponse(hRequest, NULL);
        }

        bool success = (bResults == TRUE);

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        return success;
    }

    // ⭐ 改进：带重试的远程验证
    static bool VerifyWithSupabaseRetry(const std::string& machine_code, const std::string& auth_code, int max_retries = 2) {
        for (int attempt = 1; attempt <= max_retries; attempt++) {
            bool result = VerifyWithSupabase(machine_code, auth_code);


            if (result) {
                return true; // 验证成功
            }

            // 失败后等待再重试
            if (attempt < max_retries) {
                Sleep(1000); // 等待1秒后重试
            }
        }

        // 所有重试都失败，清除本地授权并更新远程状态
        DeleteStoredAuthCode();

        // 尝试更新远程状态为false（带重试）
        for (int i = 0; i < 2; i++) {
            if (UpdateRemoteAuthStatus(machine_code, false)) {
                break;
            }
            Sleep(500);
        }

        return false;
    }


    // 关键函数：验证授权状态（单次尝试）
    static bool VerifyWithSupabase(const std::string& machine_code, const std::string& auth_code) {
        HINTERNET hSession = WinHttpOpen(
            L"HealBot/1.0",
            WINHTTP_ACCESS_TYPE_DEFAULT_PROXY,
            WINHTTP_NO_PROXY_NAME,
            WINHTTP_NO_PROXY_BYPASS, 0);

        if (!hSession) return false;

        HINTERNET hConnect = WinHttpConnect(
            hSession,
            L"heal-bo-service-ftrskdkhwk.cn-hangzhou.fcapp.run",
            INTERNET_DEFAULT_HTTPS_PORT, 0);

        if (!hConnect) {
            WinHttpCloseHandle(hSession);
            return false;
        }

        HINTERNET hRequest = WinHttpOpenRequest(
            hConnect,
            L"POST",
            L"/verify",
            NULL, WINHTTP_NO_REFERER,
            WINHTTP_DEFAULT_ACCEPT_TYPES,
            WINHTTP_FLAG_SECURE);

        if (!hRequest) {
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 🎯 关键1: 生成随机挑战值
        srand((unsigned int)time(NULL) + GetTickCount());
        uint32_t challenge = ((rand() & 0xFFFF) << 16) | (rand() & 0xFFFF);  // 32位随机数

        // 构建请求体（包含挑战值）
        std::stringstream ss;
        ss << "{\"machine_code\":\"" << machine_code
            << "\",\"auth_code\":\"" << auth_code
            << "\",\"challenge\":" << challenge << "}";
        std::string json_body = ss.str();

        std::wstring headers = L"Content-Type: application/json";

        BOOL bResults = WinHttpSendRequest(
            hRequest,
            headers.c_str(),
            -1,
            (LPVOID)json_body.c_str(),
            static_cast<DWORD>(json_body.length()),
            static_cast<DWORD>(json_body.length()),
            0);

        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        bResults = WinHttpReceiveResponse(hRequest, NULL);
        if (!bResults) {
            WinHttpCloseHandle(hRequest);
            WinHttpCloseHandle(hConnect);
            WinHttpCloseHandle(hSession);
            return false;
        }

        // 读取响应
        std::string response;
        DWORD dwSize = 0;
        DWORD dwDownloaded = 0;
        char* pszOutBuffer = new char[8192];

        do {
            dwSize = 0;
            if (WinHttpQueryDataAvailable(hRequest, &dwSize) && dwSize > 0) {
                if (WinHttpReadData(hRequest, pszOutBuffer, dwSize, &dwDownloaded)) {
                    response.append(pszOutBuffer, dwDownloaded);
                }
            }
        } while (dwSize > 0);

        delete[] pszOutBuffer;

        WinHttpCloseHandle(hRequest);
        WinHttpCloseHandle(hConnect);
        WinHttpCloseHandle(hSession);

        // ⭐ 添加调试日志
        // std::string debug_msg = "服务器响应: " + response;
        // MessageBoxA(nullptr, debug_msg.c_str(), "调试", MB_OK);

        // 🎯 关键2: 解析服务器的响应值（不再是 "valid"）
        int server_response = SimpleJSONParser::GetIntValue(response, "response");

        // 🎯 关键3: 本地计算期望值
        uint32_t expected_response = ComputeChallengeResponse(challenge, machine_code);

        // 🎯 关键4: 验证
        bool is_valid = (server_response == static_cast<int>(expected_response));

        return is_valid;
    }

    static void DeleteStoredAuthCode() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_WRITE, &hKey) == ERROR_SUCCESS) {
            RegDeleteValueA(hKey, AUTH_VALUE);
            RegCloseKey(hKey);
        }
    }

    // 新增：保存最后验证时间
    static void SaveLastVerifyTime() {
        HKEY hKey;
        if (RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) == ERROR_SUCCESS) {

            DWORD timestamp = static_cast<DWORD>(time(nullptr));
            RegSetValueExA(hKey, LAST_VERIFY_TIME, 0, REG_DWORD,
                reinterpret_cast<const BYTE*>(&timestamp), sizeof(DWORD));
            RegCloseKey(hKey);
        }
    }

    // 新增：是否可以跳过本次验证
    static bool ShouldSkipVerification() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return false;
        }

        DWORD last_time = 0;
        DWORD data_size = sizeof(DWORD);
        DWORD data_type;

        bool can_skip = false;
        if (RegQueryValueExA(hKey, LAST_VERIFY_TIME, NULL, &data_type,
            reinterpret_cast<BYTE*>(&last_time), &data_size) == ERROR_SUCCESS) {

            DWORD current_time = static_cast<DWORD>(time(nullptr));
            can_skip = (current_time - last_time) < VERIFY_INTERVAL_SECONDS;
        }

        RegCloseKey(hKey);
        return can_skip;
    }

public:
    // 生成机器ID
    static std::string GenerateMachineID() {
        std::string machine_info;

        char cpu_id[64] = { 0 };
        GetCPUInfo(cpu_id, sizeof(cpu_id));
        machine_info += cpu_id;

        char hdd_serial[64] = { 0 };
        GetHDDSerialNumber(hdd_serial, sizeof(hdd_serial));
        machine_info += hdd_serial;

        char mac_addr[32] = { 0 };
        GetMACAddress(mac_addr, sizeof(mac_addr));
        machine_info += mac_addr;

        char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computer_name);
        if (GetComputerNameA(computer_name, &size)) {
            machine_info += computer_name;
        }

        uint32_t hash = SimpleHash(machine_info);
        char machine_id[16];
        sprintf_s(machine_id, "%012llX", static_cast<unsigned long long>(hash) & 0xFFFFFFFFFFFFULL);

        return std::string(machine_id);
    }

    // 验证授权码
    static bool VerifyAuthCode(const std::string& auth_code, const std::string& machine_id) {
        try {
            std::string decrypted = CustomCrypto::Decrypt(auth_code, machine_id);
            return (decrypted == SECRET_PASSWORD);
        }
        catch (...) {
            return false;
        }
    }

    // ⭐ 核心改进：启动时的授权检查（每次都远程验证）
    static bool IsAuthorized() {
        std::string machine_id = GenerateMachineID();
        std::string stored_auth = GetStoredAuthCode();

        if (stored_auth.empty()) {
            return false; // 没有本地授权码
        }

        // ⭐ 关键：每次启动都进行远程验证（带2次重试）
        // 不再信任本地缓存，必须联网验证
        bool remote_valid = VerifyWithSupabaseRetry(machine_id, stored_auth, 2);

        if (!remote_valid) {
            // 远程验证失败，本地授权已被清除
            return false;
        }

        // 二次本地验证（防止网络劫持）
        return VerifyAuthCode(stored_auth, machine_id);
    }

    // 保存授权码
    static bool SaveAuthCode(const std::string& auth_code) {
        HKEY hKey;
        LONG result = RegCreateKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, NULL,
            REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL);

        if (result != ERROR_SUCCESS) {
            return false;
        }

        result = RegSetValueExA(hKey, AUTH_VALUE, 0, REG_SZ,
            reinterpret_cast<const BYTE*>(auth_code.c_str()),
            static_cast<DWORD>(auth_code.length() + 1));

        RegCloseKey(hKey);
        return (result == ERROR_SUCCESS);
    }

    // 显示授权对话框
    static bool ShowAuthDialog(HWND parent) {
        std::string machine_id = GenerateMachineID();
        return ShowAuthWindow(parent, machine_id);
    }

private:
    // 创建授权窗口
    static bool ShowAuthWindow(HWND parent, const std::string& machine_id) {
        const char* className = "AuthWindowClass";
        WNDCLASSA wc = { 0 };
        wc.lpfnWndProc = AuthWindowProc;
        wc.hInstance = GetModuleHandle(NULL);
        wc.lpszClassName = className;
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(NULL, IDC_ARROW);
        wc.hIcon = LoadIcon(NULL, IDI_APPLICATION);

        if (!RegisterClassA(&wc)) {
            // 可能已经注册过了，忽略错误
        }

        AuthDialogData* pData = new AuthDialogData();
        pData->machine_id = machine_id;
        pData->result = false;

        int width = 520;
        int height = 320;
        int x = (GetSystemMetrics(SM_CXSCREEN) - width) / 2;
        int y = (GetSystemMetrics(SM_CYSCREEN) - height) / 2;

        HWND hWnd = CreateWindowA(
            className,
            "软件授权验证",
            WS_OVERLAPPED | WS_CAPTION | WS_SYSMENU,
            x, y, width, height,
            parent, NULL, GetModuleHandle(NULL), pData
        );

        if (!hWnd) {
            delete pData;
            MessageBoxA(parent, "创建授权窗口失败", "错误", MB_OK | MB_ICONERROR);
            return false;
        }

        ShowWindow(hWnd, SW_SHOW);
        UpdateWindow(hWnd);

        MSG msg;
        bool dialogRunning = true;
        while (dialogRunning && GetMessage(&msg, NULL, 0, 0)) {
            if (msg.hwnd == hWnd || IsChild(hWnd, msg.hwnd)) {
                if (msg.message == WM_USER + 100) {
                    pData->result = true;
                    dialogRunning = false;
                }
                else if (msg.message == WM_USER + 101) {
                    pData->result = false;
                    dialogRunning = false;
                }
            }

            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

        bool result = pData->result;
        delete pData;

        if (IsWindow(hWnd)) {
            DestroyWindow(hWnd);
        }

        return result;
    }

    // 授权窗口过程

    static LRESULT CALLBACK AuthWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        static AuthDialogData* pData = nullptr;

        switch (msg) {
        case WM_CREATE:
        {
            CREATESTRUCT* cs = (CREATESTRUCT*)lParam;
            pData = (AuthDialogData*)cs->lpCreateParams;
            pData->hDlg = hwnd;

            CreateAuthControls(hwnd, pData);
            SetFocus(pData->hAuthEdit);
            return 0;
        }

        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_COPY_MACHINE_ID:
                if (pData) {
                    CopyToClipboard(hwnd, pData->machine_id);
                    MessageBoxA(hwnd, "机器码已复制到剪贴板", "复制成功", MB_OK | MB_ICONINFORMATION);
                }
                break;

            case IDOK:
            {
                char auth_code[512] = { 0 };
                GetWindowTextA(pData->hAuthEdit, auth_code, sizeof(auth_code));

                std::string auth_str = auth_code;
                auth_str.erase(0, auth_str.find_first_not_of(" \t\r\n"));
                if (!auth_str.empty()) {
                    auth_str.erase(auth_str.find_last_not_of(" \t\r\n") + 1);
                }

                if (auth_str.empty()) {
                    MessageBoxA(hwnd, "请输入授权码", "提示", MB_OK | MB_ICONWARNING);
                    SetFocus(pData->hAuthEdit);
                    break;
                }

                // 本地格式验证
                if (!VerifyAuthCode(auth_str, pData->machine_id)) {
                    MessageBoxA(hwnd,
                        "授权码格式错误或与机器码不匹配！\n请检查授权码是否正确",
                        "本地验证失败", MB_OK | MB_ICONERROR);
                    SetWindowTextA(pData->hAuthEdit, "");
                    SetFocus(pData->hAuthEdit);
                    break;
                }

                // ⭐ 禁用控件，显示验证状态
                EnableWindow(pData->hAuthEdit, FALSE);
                EnableWindow(GetDlgItem(hwnd, IDOK), FALSE);
                EnableWindow(GetDlgItem(hwnd, IDCANCEL), FALSE);
                SetWindowTextA(GetDlgItem(hwnd, IDOK), "验证中...");

                // ⭐ 异步验证数据结构
                struct VerifyData {
                    HWND hwnd;
                    std::string machine_id;
                    std::string auth_code;
                };

                VerifyData* vData = new VerifyData();
                vData->hwnd = hwnd;
                vData->machine_id = pData->machine_id;
                vData->auth_code = auth_str;

                // ⭐ 后台验证线程
                std::thread([](VerifyData* vData) {
                    bool remote_valid = VerifyWithSupabaseRetry(vData->machine_id, vData->auth_code, 2);

                    if (remote_valid) {
                        if (SaveAuthCode(vData->auth_code)) {
                            PostMessage(vData->hwnd, WM_USER + 200, 1, 0); // 成功
                        }
                        else {
                            PostMessage(vData->hwnd, WM_USER + 200, 2, 0); // 保存失败
                        }
                    }
                    else {
                        PostMessage(vData->hwnd, WM_USER + 200, 0, 0); // 验证失败
                    }

                    delete vData;
                    }, vData).detach();
            }
            break;

            case IDCANCEL:
                PostMessage(hwnd, WM_USER + 101, 0, 0);
                break;
            }
            break;

        case WM_USER + 200: // ⭐ 验证结果处理
        {
            // 恢复UI
            EnableWindow(pData->hAuthEdit, TRUE);
            EnableWindow(GetDlgItem(hwnd, IDOK), TRUE);
            EnableWindow(GetDlgItem(hwnd, IDCANCEL), TRUE);
            SetWindowTextA(GetDlgItem(hwnd, IDOK), "确定");

            if (wParam == 1) {
                // 成功
                MessageBoxA(hwnd,
                    "授权成功！\n软件已激活，可以正常使用",
                    "授权成功", MB_OK | MB_ICONINFORMATION);
                PostMessage(hwnd, WM_USER + 100, 0, 0);
            }
            else if (wParam == 2) {
                // 保存失败
                MessageBoxA(hwnd,
                    "保存授权码失败，请检查程序权限",
                    "保存失败", MB_OK | MB_ICONERROR);
                SetWindowTextA(pData->hAuthEdit, "");
                SetFocus(pData->hAuthEdit);
            }
            else {
                // 验证失败
                MessageBoxA(hwnd,
                    "授权验证失败！\n\n可能的原因：\n"
                    "1. 该授权已被管理员取消\n"
                    "2. 授权码未在系统中注册\n"
                    "3. 网络连接失败（已重试2次）\n\n"
                    "请联系管理员确认授权状态",
                    "远程验证失败", MB_OK | MB_ICONERROR);
                SetWindowTextA(pData->hAuthEdit, "");
                SetFocus(pData->hAuthEdit);
            }
        }
        break;

        case WM_CLOSE:
            PostMessage(hwnd, WM_USER + 101, 0, 0);
            break;

        default:
            return DefWindowProc(hwnd, msg, wParam, lParam);
        }

        return 0;
    }

    // 创建授权控件
    static void CreateAuthControls(HWND hwnd, AuthDialogData* pData) {
        HINSTANCE hInst = GetModuleHandle(NULL);

        // 标题
        CreateWindowA("STATIC", "软件需要授权才能使用",
            WS_CHILD | WS_VISIBLE | SS_CENTER,
            20, 20, 460, 25, hwnd, NULL, hInst, NULL);

        // 机器码标签
        CreateWindowA("STATIC", "您的机器码（请发送给开发者获取授权码）:",
            WS_CHILD | WS_VISIBLE,
            20, 60, 350, 20, hwnd, NULL, hInst, NULL);

        // 机器码输入框
        pData->hMachineEdit = CreateWindowA("EDIT", pData->machine_id.c_str(),
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY | ES_CENTER,
            20, 85, 350, 25, hwnd, (HMENU)IDC_MACHINE_ID_EDIT, hInst, NULL);

        // 复制按钮
        CreateWindowA("BUTTON", "复制机器码",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON,
            380, 85, 100, 25, hwnd, (HMENU)IDC_COPY_MACHINE_ID, hInst, NULL);

        // 分隔线
        CreateWindowA("STATIC", "",
            WS_CHILD | WS_VISIBLE | SS_ETCHEDHORZ,
            20, 130, 460, 2, hwnd, NULL, hInst, NULL);

        // 授权码标签
        CreateWindowA("STATIC", "请输入开发者提供的授权码:",
            WS_CHILD | WS_VISIBLE,
            20, 150, 250, 20, hwnd, NULL, hInst, NULL);

        // 授权码输入框
        pData->hAuthEdit = CreateWindowA("EDIT", "",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP,
            20, 175, 460, 25, hwnd, (HMENU)IDC_AUTH_CODE_EDIT, hInst, NULL);

        // 按钮区域
        CreateWindowA("BUTTON", "确定",
            WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | WS_TABSTOP,
            300, 220, 80, 30, hwnd, (HMENU)IDOK, hInst, NULL);

        CreateWindowA("BUTTON", "取消",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_TABSTOP,
            390, 220, 80, 30, hwnd, (HMENU)IDCANCEL, hInst, NULL);

        // 设置字体
        HFONT hFont = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
        if (hFont) {
            EnumChildWindows(hwnd, [](HWND hwnd, LPARAM lParam) -> BOOL {
                SendMessage(hwnd, WM_SETFONT, lParam, TRUE);
                return TRUE;
                }, (LPARAM)hFont);
        }
    }

    // 复制到剪贴板
    static void CopyToClipboard(HWND hwnd, const std::string& text) {
        if (OpenClipboard(hwnd)) {
            EmptyClipboard();

            HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.length() + 1);
            if (hMem) {
                char* pMem = static_cast<char*>(GlobalLock(hMem));
                if (pMem) {
                    strcpy_s(pMem, text.length() + 1, text.c_str());
                    GlobalUnlock(hMem);
                    SetClipboardData(CF_TEXT, hMem);
                }
            }

            CloseClipboard();
        }
    }

    // 工具函数
    static uint32_t SimpleHash(const std::string& input) {
        uint32_t hash = 2166136261u;
        for (char c : input) {
            hash ^= static_cast<uint8_t>(c);
            hash *= 16777619u;
        }
        return hash;
    }

    static void GetCPUInfo(char* buffer, size_t size) {
        int cpu_info[4] = { 0 };
        __try {
            __cpuid(cpu_info, 1);
            sprintf_s(buffer, size, "%08X%08X", cpu_info[0], cpu_info[3]);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            SYSTEM_INFO sys_info;
            GetSystemInfo(&sys_info);
            sprintf_s(buffer, size, "%08X%08X",
                sys_info.dwProcessorType,
                sys_info.dwNumberOfProcessors);
        }
    }

    static void GetHDDSerialNumber(char* buffer, size_t size) {
        DWORD serial_number = 0;
        if (GetVolumeInformationA("C:\\", NULL, 0, &serial_number, NULL, NULL, NULL, 0)) {
            sprintf_s(buffer, size, "%08X", serial_number);
        }
        else {
            strcpy_s(buffer, size, "NOHDD001");
        }
    }

    static void GetMACAddress(char* buffer, size_t size) {
        PIP_ADAPTER_INFO adapter_info = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
        DWORD buf_len = sizeof(IP_ADAPTER_INFO);

        if (GetAdaptersInfo(adapter_info, &buf_len) == ERROR_BUFFER_OVERFLOW) {
            free(adapter_info);
            adapter_info = (IP_ADAPTER_INFO*)malloc(buf_len);
        }

        if (GetAdaptersInfo(adapter_info, &buf_len) == ERROR_SUCCESS) {
            sprintf_s(buffer, size, "%02X%02X%02X%02X%02X%02X",
                adapter_info->Address[0], adapter_info->Address[1],
                adapter_info->Address[2], adapter_info->Address[3],
                adapter_info->Address[4], adapter_info->Address[5]);
        }
        else {
            strcpy_s(buffer, size, "NOMAC001");
        }

        free(adapter_info);
    }

public:
    static std::string GetStoredAuthCode() {
        HKEY hKey;
        if (RegOpenKeyExA(HKEY_CURRENT_USER, REGISTRY_KEY, 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return "";
        }

        char auth_code[512];
        DWORD data_size = sizeof(auth_code);
        DWORD data_type;

        LONG result = RegQueryValueExA(hKey, AUTH_VALUE, NULL, &data_type,
            reinterpret_cast<BYTE*>(auth_code), &data_size);

        RegCloseKey(hKey);

        if (result == ERROR_SUCCESS && data_type == REG_SZ) {
            return std::string(auth_code);
        }

        return "";
    }
};

// 授权码生成器（你使用的工具）
class AuthCodeGenerator {
public:
    static std::string GenerateAuthCode(const std::string& machine_id) {
        return CustomCrypto::Encrypt("HEALBOT_2024_MASTER_SECRET", machine_id);
    }

    // 批量生成授权码
    static void GenerateBatchAuthCodes() {
        // 示例机器ID
        std::vector<std::string> test_machine_ids = {
            "1A2B3C4D5E6F", "9F8E7D6C5B4A", "ABCDEF123456"
        };

        std::cout << "=== 授权码生成器 ===" << std::endl;
        for (const auto& machine_id : test_machine_ids) {
            std::string auth_code = GenerateAuthCode(machine_id);
            std::cout << "机器ID: " << machine_id << std::endl;
            std::cout << "授权码: " << auth_code << std::endl;
            std::cout << "------------------------" << std::endl;
        }
    }
};


// 简单JSON类
class SimpleJSON {
private:
    std::map<std::string, std::string> data_;

public:
    void SetString(const std::string& key, const std::string& value) {
        data_[key] = "\"" + value + "\"";
    }

    void SetInt(const std::string& key, int value) {
        data_[key] = std::to_string(value);
    }

    void SetBool(const std::string& key, bool value) {
        data_[key] = value ? "true" : "false";
    }

    std::string GetString(const std::string& key, const std::string& defaultValue = "") const {
        auto it = data_.find(key);
        if (it != data_.end()) {
            std::string val = it->second;
            // 移除引号
            if (val.length() >= 2 && val[0] == '"' && val.back() == '"') {
                return val.substr(1, val.length() - 2);
            }
            return val;
        }
        return defaultValue;
    }

    int GetInt(const std::string& key, int defaultValue = 0) const {
        auto it = data_.find(key);
        if (it != data_.end()) {
            try {
                return std::stoi(it->second);
            }
            catch (...) {
                return defaultValue;
            }
        }
        return defaultValue;
    }

    bool GetBool(const std::string& key, bool defaultValue = false) const {
        auto it = data_.find(key);
        if (it != data_.end()) {
            return it->second == "true";
        }
        return defaultValue;
    }

    std::string ToString() const {
        std::stringstream ss;
        ss << "{\n";
        bool first = true;
        for (const auto& pair : data_) {
            if (!first) ss << ",\n";
            ss << "  \"" << pair.first << "\": " << pair.second;
            first = false;
        }
        ss << "\n}";
        return ss.str();
    }

    bool FromString(const std::string& json) {
        data_.clear();

        if (json.empty()) {
            return false;
        }

        // 检查基本JSON结构
        size_t openBrace = json.find('{');
        size_t closeBrace = json.find_last_of('}');
        if (openBrace == std::string::npos || closeBrace == std::string::npos || openBrace >= closeBrace) {
            return false;
        }

        std::string content = json.substr(openBrace + 1, closeBrace - openBrace - 1);
        size_t pos = 0;

        // 更健壮的解析逻辑
        while (pos < content.length()) {
            // 跳过空白字符
            while (pos < content.length() && (content[pos] == ' ' || content[pos] == '\t' ||
                content[pos] == '\n' || content[pos] == '\r' || content[pos] == ',')) {
                pos++;
            }

            if (pos >= content.length()) break;

            // 查找键的开始 "
            size_t keyStart = content.find('"', pos);
            if (keyStart == std::string::npos) break;

            // 查找键的结束 "
            size_t keyEnd = content.find('"', keyStart + 1);
            if (keyEnd == std::string::npos) break;

            std::string key = content.substr(keyStart + 1, keyEnd - keyStart - 1);

            // 查找冒号
            size_t colonPos = content.find(':', keyEnd);
            if (colonPos == std::string::npos) break;

            // 跳过空白到值的开始
            size_t valueStart = colonPos + 1;
            while (valueStart < content.length() &&
                (content[valueStart] == ' ' || content[valueStart] == '\t' || content[valueStart] == '\n')) {
                valueStart++;
            }

            if (valueStart >= content.length()) break;

            std::string value;
            if (content[valueStart] == '"') {
                // 字符串值
                size_t valueEnd = content.find('"', valueStart + 1);
                if (valueEnd == std::string::npos) break;
                value = "\"" + content.substr(valueStart + 1, valueEnd - valueStart - 1) + "\"";
                pos = valueEnd + 1;
            }
            else {
                // 数字或布尔值
                size_t valueEnd = valueStart;
                while (valueEnd < content.length() &&
                    content[valueEnd] != ',' && content[valueEnd] != '}' && content[valueEnd] != '\n') {
                    valueEnd++;
                }
                value = content.substr(valueStart, valueEnd - valueStart);

                // 去除尾部空白
                while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r')) {
                    value.pop_back();
                }

                pos = valueEnd;
            }

            // 验证键和值不为空
            if (!key.empty() && !value.empty()) {
                data_[key] = value;
            }

            // 移动到下一个可能的键值对
            pos++;
        }

        return !data_.empty();
    }

    bool LoadFromFile(const std::string& filename) {
        std::ifstream file(filename);
        if (!file.is_open()) {
            // 文件打开失败
            return false;
        }

        std::string content((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();

        // 检查文件内容是否为空
        if (content.empty()) {
            return false;
        }

        // 检查是否包含基本的JSON结构
        if (content.find('{') == std::string::npos || content.find('}') == std::string::npos) {
            return false;
        }

        bool result = FromString(content);

        // 额外验证：确保解析后有数据
        if (result && data_.empty()) {
            return false;
        }

        return result;
    }

    bool SaveToFile(const std::string& filename) const {
        std::ofstream file(filename);
        if (!file.is_open()) return false;

        file << ToString();
        file.close();
        return true;
    }
};

// 治疗配置结构
struct HealConfig {
    bool enabled;          // 是否启用
    int threshold;         // 血量/蓝量阈值(%)
    WORD key_code;         // 按键码
    std::string key_name;  // 按键显示名称
    std::string description; // 描述信息
    int cooldown_seconds;  // 隐匿冷却时间（秒），0表示无冷却

    HealConfig() : enabled(true), threshold(95), key_code(VK_F9), key_name("F9"), description("普通治疗"), cooldown_seconds(0) {}

    HealConfig(bool en, int th, WORD key, const std::string& name, const std::string& desc, int cd = 0)
        : enabled(en), threshold(th), key_code(key), key_name(name), description(desc), cooldown_seconds(cd) {
    }
};

// 性能配置
struct PerformanceConfig {
    static constexpr int DETECTION_INTERVAL_US = 10;      // 5ms检测间隔
    static constexpr int DATA_UPDATE_INTERVAL_US = 10;    // 1ms数据更新间隔
    static constexpr int KEY_SENDER_TIMEOUT_MS = 5;        // 10ms按键超时
    static constexpr int KEY_SENDER_INTERVAL_US = 1;      // 100us按键间隔
    static constexpr int DEBUG_OUTPUT_FREQUENCY = 6000;     // 每2000次输出调试信息
};

// 进程信息结构
struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string start_time;
    std::string window_title;
    HANDLE handle;
    uintptr_t base_address;
    bool is_valid;

    ProcessInfo() : pid(0), handle(nullptr), base_address(0), is_valid(false) {}
};

// 双队列设计 - 紧急队列 + 普通队列
class DualHealQueue {
public:
    struct HealCommand {
        int priority;      // 优先级 1=最高, 5=最低
        WORD key_code;
        std::string description;
        int current_value;
        int max_value;

        bool operator<(const HealCommand& other) const {
            return priority > other.priority;  // 优先级越小越优先
        }
    };

private:
    std::priority_queue<HealCommand> emergency_queue_;  // 紧急队列 (优先级1-2)
    std::priority_queue<HealCommand> normal_queue_;     // 普通队列 (优先级3-5)
    mutable std::mutex queue_mutex_;
    std::atomic<size_t> total_enqueued_{ 0 };
    std::atomic<size_t> total_dequeued_{ 0 };

public:
    void ClearNormalQueue() {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        // 清空普通队列
        while (!normal_queue_.empty()) {
            normal_queue_.pop();
        }
    }

    void ClearAllQueues() {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        while (!emergency_queue_.empty()) {
            emergency_queue_.pop();
        }
        while (!normal_queue_.empty()) {
            normal_queue_.pop();
        }
    }

    void Enqueue(int priority, WORD key_code, const std::string& description, int current_val, int max_val) {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        HealCommand cmd = { priority, key_code, description, current_val, max_val };

        // ⭐ 关键：根据优先级分配到不同队列
        if (priority <= 2) {
            // 优先级1-2 进入紧急队列
            emergency_queue_.push(cmd);
        }
        else {
            // 优先级3-5 进入普通队列
            normal_queue_.push(cmd);
        }

        total_enqueued_++;
    }

    bool Dequeue(HealCommand& command) {
        std::lock_guard<std::mutex> lock(queue_mutex_);

        // ⭐ 关键：优先从紧急队列取指令
        if (!emergency_queue_.empty()) {
            command = emergency_queue_.top();
            emergency_queue_.pop();
            total_dequeued_++;
            return true;
        }

        // 紧急队列空了，再从普通队列取
        if (!normal_queue_.empty()) {
            command = normal_queue_.top();
            normal_queue_.pop();
            total_dequeued_++;
            return true;
        }

        return false;
    }

    void GetStats(size_t& enqueued, size_t& dequeued, size_t& pending) const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        enqueued = total_enqueued_.load();
        dequeued = total_dequeued_.load();
        pending = emergency_queue_.size() + normal_queue_.size();
    }

    // ⭐ 新增：获取紧急队列大小（用于调试）
    size_t GetEmergencyQueueSize() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return emergency_queue_.size();
    }

    // ⭐ 新增：获取普通队列大小（用于调试）
    size_t GetNormalQueueSize() const {
        std::lock_guard<std::mutex> lock(queue_mutex_);
        return normal_queue_.size();
    }
};

// 全局变量定义
ConfigurableHealBotUI* g_ui_instance = nullptr;

// 可配置加血机器人类
class ConfigurableHealBot {
private:
    // 游戏配置 - 固定内存偏移
    static constexpr DWORD HP_OFFSET = 0x15235AC;
    static constexpr DWORD MAXHP_OFFSET = 0x15235B0;
    static constexpr DWORD SP_OFFSET = 0x15235B4;
    static constexpr DWORD MAXSP_OFFSET = 0x15235B8;
    static constexpr DWORD MAP_OFFSET = 0x151FA14;

    PeriodicAuthVerifier periodic_verifier_;  // ⭐ 后台验证器

    std::atomic<int> sp_commands_in_queue_{ 0 };
    static constexpr int MAX_SP_IN_QUEUE = 4; // 最多允许4个SP指令在队列中

    std::atomic<int> normal_hp_commands_in_queue_{ 0 };  // 新增：普通HP计数器
    static constexpr int MAX_NORMAL_HP_IN_QUEUE = 10;    // 新增：普通HP上限为10

    // 游戏数据结构
    struct GameData {
        std::atomic<int> current_hp{ 0 };
        std::atomic<int> max_hp{ 0 };
        std::atomic<int> current_sp{ 0 };
        std::atomic<int> max_sp{ 0 };
        std::atomic<bool> is_valid{ false };
        std::atomic<bool> running{ false };

        // 新增地图状态
        char map_name[64] = { 0 };         // 当前地图名称
        std::atomic<bool> is_valid_map{ false };  // 是否在有效地图（all_valid_maps）
        std::atomic<bool> is_cas_map{ false };    // 是否在城堡地图（cas_maps）
    };

    // 地图验证配置
    std::vector<std::string> all_valid_maps_ = {
        "aru_gld", "arug_cas", "sch_gld", "schg_cas", "prt_gld", "prtg_cas"
    };
    std::vector<std::string> cas_maps_ = {
        "arug_cas", "schg_cas", "prtg_cas"
    };

    // 借鉴的地图验证方法
    bool IsValidMap(const std::string& map_name, const std::vector<std::string>& valid_prefixes) const {
        if (map_name.empty()) return false;
        for (const auto& prefix : valid_prefixes) {
            if (map_name.length() >= prefix.length() &&
                map_name.substr(0, prefix.length()) == prefix) {
                return true;
            }
        }
        return false;
    }

    HWND target_window_;          // 目标窗口句柄
    GameData game_data_;          // 游戏数据
    ProcessInfo target_process_;  // 目标进程信息
    DualHealQueue  heal_queue_; // 治疗队列

    std::thread data_thread_;     // 数据读取线程
    std::thread heal_thread_;     // 治疗处理线程

    // 治疗配置
    HealConfig normal_heal_;      // 普通治疗
    HealConfig enhanced_heal_;    // 增强治疗
    HealConfig emergency1_heal_;  // 紧急治疗1
    HealConfig emergency2_heal_;  // 紧急治疗2
    HealConfig sp_heal_;          // SP恢复
    HealConfig skill_trigger_;  // 技能触发配置

    // 冷却管理（使用unordered_map支持多个带冷却的技能）
    std::unordered_map<WORD, std::chrono::steady_clock::time_point> last_skill_trigger_time_;

    // 紧急药品1秒间隔
    std::unordered_map<WORD, std::chrono::steady_clock::time_point> last_emergency_enqueue_time_;
    static constexpr int EMERGENCY_ENQUEUE_INTERVAL_MS = 100; // 紧急药品间隔

public:
    ConfigurableHealBot() : target_window_(nullptr) {
        // 初始化默认配置
        normal_heal_ = HealConfig(true, 95, VK_F9, "F9", "普通治疗");
        enhanced_heal_ = HealConfig(true, 95, VK_F8, "F8", "增强治疗");
        emergency1_heal_ = HealConfig(true, 55, VK_F7, "F7", "紧急治疗1");
        emergency2_heal_ = HealConfig(true, 45, VK_F10, "F10", "紧急治疗2");
        sp_heal_ = HealConfig(true, 85, VK_F8, "F8", "SP恢复");
        skill_trigger_ = HealConfig(false, 50, VK_F6, "F6", "技能触发", 5);  // 默认关闭，50%血量，F6键，5秒冷却
    }

    ~ConfigurableHealBot() {
        Stop();  // 先停止线程

        // ✅ 添加这段（第2处修改）- 程序退出时才真正关闭句柄
        if (target_process_.handle) {
            CloseHandle(target_process_.handle);
            target_process_.handle = nullptr;
        }
    }

    // 更新治疗配置
    void UpdateConfig(const HealConfig& normal, const HealConfig& enhanced,
        const HealConfig& emergency1, const HealConfig& emergency2,
        const HealConfig& sp, const HealConfig& skill) {
        normal_heal_ = normal;
        enhanced_heal_ = enhanced;
        emergency1_heal_ = emergency1;
        emergency2_heal_ = emergency2;
        sp_heal_ = sp;
        skill_trigger_ = skill;
    }

    // 获取当前配置
    void GetConfig(HealConfig& normal, HealConfig& enhanced,
        HealConfig& emergency1, HealConfig& emergency2,
        HealConfig& sp, HealConfig& skill) const {
        normal = normal_heal_;
        enhanced = enhanced_heal_;
        emergency1 = emergency1_heal_;
        emergency2 = emergency2_heal_;
        sp = sp_heal_;
        skill = skill_trigger_;
    }

    void UpdateConfigRuntime(const HealConfig& normal, const HealConfig& enhanced,
        const HealConfig& emergency1, const HealConfig& emergency2,
        const HealConfig& sp, const HealConfig& skill) {
        // 更新配置
        normal_heal_ = normal;
        enhanced_heal_ = enhanced;
        emergency1_heal_ = emergency1;
        emergency2_heal_ = emergency2;
        sp_heal_ = sp;
        skill_trigger_ = skill;

        // 如果正在运行，立即生效
        if (game_data_.running.load()) {
            LogMessage("配置已实时更新并生效!");
        }
    }

    bool StartWithProcess(const ProcessInfo& process_info) {
        if (game_data_.running.load()) {
            LogMessage("机器人已在运行中!");
            return false;
        }

        std::string machine_id = SoftwareAuth::GenerateMachineID();
        std::string auth_code = SoftwareAuth::GetStoredAuthCode();
        //暂时移除
        //if (!periodic_verifier_.Start(machine_id, auth_code)) {
            //LogMessage("❌ 后台验证启动失败");
            //return false;
        //}


        target_process_ = process_info;
        target_window_ = FindWindowForProcess(process_info.pid);

        if (!target_window_) {
            LogMessage("警告: 未找到进程窗口，将使用全局按键");
        }
        else {
            LogMessage("已找到目标窗口，将直接发送按键到进程");
        }

        game_data_.running.store(true);

        LogMessage("启动加血机器人 PID: " + std::to_string(process_info.pid));
        LogMessage("基地址: 0x" + std::to_string(process_info.base_address));

        // 启动线程
        data_thread_ = std::thread(&ConfigurableHealBot::DataThread, this);
        heal_thread_ = std::thread(&ConfigurableHealBot::HealThread, this);

        LogMessage("可配置加血机器人已启动 - 后台SPAM模式!");
        return true;
    }

    void Stop() {
        if (!game_data_.running.load()) return;

        LogMessage("停止加血机器人...");
        game_data_.running.store(false);

        // 停止后台验证
        // ✅ 恢复停止后台验证 暂时移除
        //periodic_verifier_.Stop();

        // 带超时的线程等待
        auto wait_with_timeout = [](std::thread& t, int timeout_ms) -> bool {
            if (!t.joinable()) return true;

            auto start = std::chrono::steady_clock::now();
            while (t.joinable()) {
                auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - start).count();

                if (elapsed > timeout_ms) {
                    LogMessage("线程超时 - 强制终止");
                    t.detach();  // 强制分离线程
                    return false;
                }
                Sleep(10);
            }
            return true;
            };

        // 尝试优雅关闭线程
        if (data_thread_.joinable()) {
            if (!wait_with_timeout(data_thread_, 1000)) {  // 1秒超时
                LogMessage("数据线程被强制分离");
            }
        }

        if (heal_thread_.joinable()) {
            if (!wait_with_timeout(heal_thread_, 1000)) {  // 1秒超时
                LogMessage("治疗线程被强制分离");
            }
        }


        target_window_ = nullptr;
        LogMessage("加血机器人已成功停止");
    }

    bool IsRunning() const {
        return game_data_.running.load();
    }

private:
    void DataThread() {
        LogMessage("[数据线程] 已启动");
        int debug_counter = 0;

        while (game_data_.running.load()) {
            ReadGameData();
            debug_counter++;

            // 减少调试输出频率 (仅在debug版本显示)
#ifdef _DEBUG
            if (debug_counter % PerformanceConfig::DEBUG_OUTPUT_FREQUENCY == 0) {
                LogMessage("[调试] HP: " + std::to_string(game_data_.current_hp.load()) +
                    "/" + std::to_string(game_data_.max_hp.load()) +
                    ", 数据有效: " + (game_data_.is_valid.load() ? "是" : "否") +
                    ", 后台模式: 启用");

                size_t enqueued, dequeued, pending;
                heal_queue_.GetStats(enqueued, dequeued, pending);
                LogMessage("[队列] 入队: " + std::to_string(enqueued) +
                    ", 已处理: " + std::to_string(dequeued) +
                    ", 等待中: " + std::to_string(pending));
            }
#endif

            std::this_thread::sleep_for(std::chrono::microseconds(PerformanceConfig::DATA_UPDATE_INTERVAL_US));
        }
        LogMessage("[数据线程] 已停止");
    }
private:
    // ⭐ 新增: 统一的出栈检查函数
    bool ShouldExecuteHeal(const DualHealQueue::HealCommand& command) {
        int current_hp = game_data_.current_hp.load();
        int max_hp = game_data_.max_hp.load();
        int current_sp = game_data_.current_sp.load();
        int max_sp = game_data_.max_sp.load();
        bool is_valid_map = game_data_.is_valid_map.load();
        bool is_cas_map = game_data_.is_cas_map.load();

        // 1. 角色死亡或离开地图 - 所有治疗都停止
        if (current_hp <= 1 || !is_valid_map) {
            return false;
        }

        // 2. 根据治疗类型进行细化检查
        int hp_percent = (current_hp * 100) / max_hp;
        int sp_percent = max_sp > 0 ? (current_sp * 100) / max_sp : 100;

        // SP治疗的特殊检查
        if (command.key_code == sp_heal_.key_code) {
            return sp_percent <= sp_heal_.threshold && is_valid_map;
        }

        // 紧急治疗2
        if (command.key_code == emergency2_heal_.key_code) {
            return hp_percent <= emergency2_heal_.threshold && is_cas_map;
        }

        // 紧急治疗1
        if (command.key_code == emergency1_heal_.key_code) {
            return hp_percent <= emergency1_heal_.threshold && is_cas_map;
        }

        // 增强治疗
        if (command.key_code == enhanced_heal_.key_code) {
            return hp_percent <= enhanced_heal_.threshold && is_cas_map;
        }

        // 普通治疗
        if (command.key_code == normal_heal_.key_code) {
            return hp_percent <= normal_heal_.threshold && is_valid_map;
        }

        // 技能触发 (已有冷却检查，这里只检查血量)
        if (command.key_code == skill_trigger_.key_code) {
            return hp_percent <= skill_trigger_.threshold && is_cas_map;
        }

        return true;  // 默认允许
    }
    // ⭐ 新增: 统一的计数器减少
    void DecrementCommandCounter(WORD key_code) {
        if (key_code == sp_heal_.key_code) {
            sp_commands_in_queue_.fetch_sub(1, std::memory_order_relaxed);
        }
        else if (key_code == normal_heal_.key_code) {
            normal_hp_commands_in_queue_.fetch_sub(1, std::memory_order_relaxed);
        }
        // 可以为其他治疗类型添加计数器
    }

    void HealThread() {
        LogMessage("[治疗线程] 已启动");
        size_t keys_sent = 0;

        while (game_data_.running.load()) {
            // 检查并加入治疗队列
            CheckAndEnqueueHeals();

            // 处理治疗队列
            DualHealQueue::HealCommand command;
            if (heal_queue_.Dequeue(command)) {
                
                // ⭐⭐⭐ 统一的出栈二次检查逻辑
                if (!ShouldExecuteHeal(command)) {
                    // 根据指令类型减少计数器
                    DecrementCommandCounter(command.key_code);
                    continue;  // 跳过这个按键
                }

                // 发送按键到目标窗口 (后台模式)
                SendKeyToTarget(command.key_code);
                DecrementCommandCounter(command.key_code);
                keys_sent++;
                // 每50次显示一次日志 (避免刷屏)
                if (keys_sent % 50 == 0) {
                    int percent = command.max_value > 0 ? (command.current_value * 100 / command.max_value) : 0;
                    LogMessage("[后台SPAM " + std::to_string(keys_sent) + "] " + command.description +
                        " - " + std::to_string(command.current_value) + "/" + std::to_string(command.max_value) +
                        " (" + std::to_string(percent) + "%) 优先级:" + std::to_string(command.priority));
                }

                std::this_thread::sleep_for(std::chrono::microseconds(PerformanceConfig::KEY_SENDER_INTERVAL_US));
            }
            else {
                std::this_thread::sleep_for(std::chrono::microseconds(PerformanceConfig::DETECTION_INTERVAL_US));
            }
        }
        LogMessage("[治疗线程] 已停止，共发送 " + std::to_string(keys_sent) + " 个按键");
    }

    void CheckAndEnqueueHeals() {
        if (!game_data_.is_valid.load()) return;

        int hp = game_data_.current_hp.load();
        int max_hp = game_data_.max_hp.load();
        int sp = game_data_.current_sp.load();
        int max_sp = game_data_.max_sp.load();

        // 获取地图状态
        bool is_valid_map = game_data_.is_valid_map.load();
        bool is_cas_map = game_data_.is_cas_map.load();


        int hp_percent = (hp * 100) / max_hp;
        int sp_percent = (sp * 100) / max_sp;
        auto now = std::chrono::steady_clock::now();

        // ⭐ 修改后的死亡/离开地图检测逻辑
        if (hp <= 1) {
            // 清空所有队列，避免过图后造成断线
            heal_queue_.ClearAllQueues();
            return;
        }


        // 检查紧急药品是否可以入队
        auto canEnqueueEmergency = [&](WORD key_code) -> bool {
            auto it = last_emergency_enqueue_time_.find(key_code);
            if (it == last_emergency_enqueue_time_.end()) {
                return true; // 第一次使用
            }
            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - it->second).count();
            return elapsed >= EMERGENCY_ENQUEUE_INTERVAL_MS;
            };

        // 普通药品入队（无限制spam）
        auto enqueueNormalHeal = [&](int priority, const HealConfig& config, int current_val, int max_val) {
            heal_queue_.Enqueue(priority, config.key_code, config.description, current_val, max_val);
            };

        // ⭐⭐⭐ 关键修改：紧急治疗2 - 最高优先级，清空普通队列
        if (emergency2_heal_.enabled && hp_percent <= emergency2_heal_.threshold && is_cas_map && hp > 100) {
            if (canEnqueueEmergency(emergency2_heal_.key_code)) {
       
                heal_queue_.Enqueue(1, emergency2_heal_.key_code, emergency2_heal_.description, hp, max_hp);
                last_emergency_enqueue_time_[emergency2_heal_.key_code] = now;

                LogMessage("🚨 紧急治疗2触发！，立即执行救命！");
            
            }
        }

        // ⭐⭐⭐ 关键修改：紧急治疗1 - 第二优先级，清空普通队列
        if (emergency1_heal_.enabled && hp_percent <= emergency1_heal_.threshold && is_cas_map && hp > 100) {
            if (canEnqueueEmergency(emergency1_heal_.key_code)) {
  
                heal_queue_.Enqueue(2, emergency1_heal_.key_code, emergency1_heal_.description, hp, max_hp);
                last_emergency_enqueue_time_[emergency1_heal_.key_code] = now;

                LogMessage("⚠️ 紧急治疗1触发");
          
            }
        }

        // 增强治疗 - 第四优先级，无限制spam
        if (enhanced_heal_.enabled && hp_percent <= enhanced_heal_.threshold && is_cas_map) {
            enqueueNormalHeal(4, enhanced_heal_, hp, max_hp);
        }

        // 普通治疗 - 第四优先级，无限制spam
        if (normal_heal_.enabled && hp_percent <= normal_heal_.threshold && is_valid_map) {
            // 只有当队列中普通HP指令少于上限时才入队
            if (normal_hp_commands_in_queue_.load() < MAX_NORMAL_HP_IN_QUEUE) {
                heal_queue_.Enqueue(4, normal_heal_.key_code,
                    normal_heal_.description, hp, max_hp);
                normal_hp_commands_in_queue_.fetch_add(1); // 计数+1
            }
        }

        // SP恢复 - 第五优先级，无限制spam
        if (sp_heal_.enabled && sp_percent <= sp_heal_.threshold && is_valid_map) {
            // 只有当队列中SP指令少于上限时才入队
            if (sp_commands_in_queue_.load() < MAX_SP_IN_QUEUE) {
                heal_queue_.Enqueue(5, sp_heal_.key_code,
                    sp_heal_.description, sp, max_sp);
                sp_commands_in_queue_.fetch_add(1); // 计数+1
            }
        }

        if (skill_trigger_.enabled && hp_percent <= skill_trigger_.threshold && is_cas_map) {
            // 检查冷却时间
            auto it = last_skill_trigger_time_.find(skill_trigger_.key_code);
            bool can_trigger = false;

            if (it == last_skill_trigger_time_.end()) {
                can_trigger = true;  // 首次使用
            }
            else {
                auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second).count();
                can_trigger = (elapsed >= skill_trigger_.cooldown_seconds);
            }

            if (can_trigger) {
                heal_queue_.Enqueue(3, skill_trigger_.key_code,
                    skill_trigger_.description + " (冷却:" + std::to_string(skill_trigger_.cooldown_seconds) + "秒)",
                    hp, max_hp);
                last_skill_trigger_time_[skill_trigger_.key_code] = now;  // 记录触发时间
            }
        }
    }

    void ReadGameData() {
        // 直接读取HP/SP数据 - 后台模式
        int hp, max_hp, sp, max_sp;
        SIZE_T bytes_read;

        bool success = true;
        success &= ReadProcessMemory(target_process_.handle, (LPCVOID)HP_OFFSET, &hp, sizeof(int), &bytes_read);
        success &= ReadProcessMemory(target_process_.handle, (LPCVOID)MAXHP_OFFSET, &max_hp, sizeof(int), &bytes_read);
        success &= ReadProcessMemory(target_process_.handle, (LPCVOID)SP_OFFSET, &sp, sizeof(int), &bytes_read);
        success &= ReadProcessMemory(target_process_.handle, (LPCVOID)MAXSP_OFFSET, &max_sp, sizeof(int), &bytes_read);
        // 新增：读取地图名称
        char map_buffer[64] = { 0 };
        bool map_success = ReadProcessMemory(target_process_.handle,
            (LPCVOID)MAP_OFFSET,
            map_buffer,
            sizeof(map_buffer) - 1,
            &bytes_read);

        if (success && max_hp >= 0 && max_sp >= 0) {
            game_data_.current_hp.store(hp);
            game_data_.max_hp.store(max_hp);
            game_data_.current_sp.store(sp);
            game_data_.max_sp.store(max_sp);
            game_data_.is_valid.store(true);

            // 更新地图状态
            if (map_success && bytes_read > 0) {
                // 安全地复制地图名称
                memset(game_data_.map_name, 0, sizeof(game_data_.map_name));
                strncpy_s(game_data_.map_name, sizeof(game_data_.map_name), map_buffer, sizeof(game_data_.map_name) - 1);

                // 借鉴的地图验证逻辑
                std::string map_str(game_data_.map_name);
                game_data_.is_valid_map.store(IsValidMap(map_str, all_valid_maps_));
                game_data_.is_cas_map.store(IsValidMap(map_str, cas_maps_));
            }
            else {
                // 地图读取失败，保持上次状态或设为false
                game_data_.is_valid_map.store(false);
                game_data_.is_cas_map.store(false);
            }
        }
        else {
            game_data_.is_valid.store(false);
            game_data_.is_valid_map.store(false);
            game_data_.is_cas_map.store(false);
        }
    }

    inline bool IsLowPercent(int current, int max, int threshold_percent) const {
        if (max <= 0 || current < 0) return false;
        return (current * 100) < (max * threshold_percent);
    }

    // 查找进程的主窗口
    HWND FindWindowForProcess(DWORD pid) {
        struct EnumData {
            DWORD target_pid;
            HWND result_hwnd;
        } data = { pid, nullptr };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            EnumData* pData = reinterpret_cast<EnumData*>(lParam);
            DWORD window_pid = 0;
            GetWindowThreadProcessId(hwnd, &window_pid);

            // 查找主窗口 (可见且有标题)
            if (window_pid == pData->target_pid && IsWindowVisible(hwnd)) {
                char windowText[256];
                if (GetWindowTextA(hwnd, windowText, sizeof(windowText)) > 0) {
                    // 确保是主窗口 (不是对话框或子窗口)
                    if (GetWindow(hwnd, GW_OWNER) == nullptr) {
                        pData->result_hwnd = hwnd;
                        return FALSE; // 停止枚举
                    }
                }
            }
            return TRUE; // 继续枚举
            }, reinterpret_cast<LPARAM>(&data));

        return data.result_hwnd;
    }

    // 发送按键到目标窗口 (后台模式)
    void SendKeyToTarget(WORD key_code) {
        if (target_window_ && IsWindow(target_window_)) {
            // 方法1: PostMessage发送到窗口 (后台首选)
            PostMessage(target_window_, WM_KEYDOWN, key_code, 0);
            //Sleep(50);  // 短暂延迟模拟按键持续时间
            PostMessage(target_window_, WM_KEYUP, key_code, 0);
        }
        else {
            // 备用方法: 全局按键事件 (如果窗口句柄无效)
            keybd_event(key_code, 0, 0, 0);
            //Sleep(50);
            keybd_event(key_code, 0, KEYEVENTF_KEYUP, 0);
        }
    }
};

// 进程扫描器
class ProcessScanner {
public:
    static std::vector<ProcessInfo> ScanRagnarokProcesses() {
        std::vector<ProcessInfo> processes;

        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return processes;

        PROCESSENTRY32 pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32);

        if (Process32First(snapshot, &pe32)) {
            do {
                char exe_name[MAX_PATH];
                WideCharToMultiByte(CP_ACP, 0, pe32.szExeFile, -1, exe_name, MAX_PATH, nullptr, nullptr);

                if (_stricmp(exe_name, "Ragexe.exe") == 0) {
                    ProcessInfo info;
                    info.pid = pe32.th32ProcessID;
                    info.name = exe_name;
                    info.start_time = GetProcessStartTime(pe32.th32ProcessID);
                    info.window_title = GetProcessWindowTitle(pe32.th32ProcessID);

                    info.handle = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, info.pid);
                    if (info.handle) {
                        info.base_address = GetProcessBaseAddress(info.handle, info.pid);
                        info.is_valid = info.base_address != 0;
                    }

                    processes.push_back(info);
                }
            } while (Process32Next(snapshot, &pe32));
        }

        CloseHandle(snapshot);
        return processes;
    }

private:
    static std::string GetProcessStartTime(DWORD pid) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (!hProcess) return "未知";

        FILETIME createTime, exitTime, kernelTime, userTime;
        if (!GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
            CloseHandle(hProcess);
            return "未知";
        }

        SYSTEMTIME stUTC, stLocal;
        FileTimeToSystemTime(&createTime, &stUTC);
        SystemTimeToTzSpecificLocalTime(NULL, &stUTC, &stLocal);

        char timeStr[64];
        sprintf_s(timeStr, "%02d:%02d:%02d", stLocal.wHour, stLocal.wMinute, stLocal.wSecond);

        CloseHandle(hProcess);
        return std::string(timeStr);
    }

    static std::string GetProcessWindowTitle(DWORD pid) {
        std::string title = "无窗口";

        struct EnumData {
            DWORD pid;
            std::string title;
        } data = { pid, "" };

        EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL {
            EnumData* pData = reinterpret_cast<EnumData*>(lParam);
            DWORD windowPid = 0;
            GetWindowThreadProcessId(hwnd, &windowPid);

            if (windowPid == pData->pid && IsWindowVisible(hwnd)) {
                char windowText[256];
                if (GetWindowTextA(hwnd, windowText, sizeof(windowText)) > 0) {
                    pData->title = windowText;
                    return FALSE;
                }
            }
            return TRUE;
            }, reinterpret_cast<LPARAM>(&data));

        return data.title.empty() ? title : data.title;
    }

    static uintptr_t GetProcessBaseAddress(HANDLE hProcess, DWORD pid) {
        HMODULE hMods[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded)) {
            return reinterpret_cast<uintptr_t>(hMods[0]);
        }
        return 0;
    }
};

// 按键名称转换工具
class KeyNameConverter {
public:
    static std::string VirtualKeyToString(WORD vk) {
        switch (vk) {
        case VK_F1: return "F1";
        case VK_F2: return "F2";
        case VK_F3: return "F3";
        case VK_F4: return "F4";
        case VK_F5: return "F5";
        case VK_F6: return "F6";
        case VK_F7: return "F7";
        case VK_F8: return "F8";
        case VK_F9: return "F9";
        case VK_F10: return "F10";
        case VK_F11: return "F11";
        case VK_F12: return "F12";
        case VK_SPACE: return "Space";
        case VK_RETURN: return "Enter";
        case VK_ESCAPE: return "Esc";
        case VK_TAB: return "Tab";
        case VK_SHIFT: return "Shift";
        case VK_CONTROL: return "Ctrl";
        case VK_MENU: return "Alt";
        default:
            if (vk >= 'A' && vk <= 'Z') {
                return std::string(1, static_cast<char>(vk));
            }
            else if (vk >= '0' && vk <= '9') {
                return std::string(1, static_cast<char>(vk));
            }
            return "Key" + std::to_string(vk);
        }
    }

    static WORD StringToVirtualKey(const std::string& str) {
        if (str == "F1") return VK_F1;
        if (str == "F2") return VK_F2;
        if (str == "F3") return VK_F3;
        if (str == "F4") return VK_F4;
        if (str == "F5") return VK_F5;
        if (str == "F6") return VK_F6;
        if (str == "F7") return VK_F7;
        if (str == "F8") return VK_F8;
        if (str == "F9") return VK_F9;
        if (str == "F10") return VK_F10;
        if (str == "F11") return VK_F11;
        if (str == "F12") return VK_F12;
        if (str == "Space") return VK_SPACE;
        if (str == "Enter") return VK_RETURN;
        if (str == "Esc") return VK_ESCAPE;
        if (str == "Tab") return VK_TAB;
        if (str == "Shift") return VK_SHIFT;
        if (str == "Ctrl") return VK_CONTROL;
        if (str == "Alt") return VK_MENU;

        if (str.length() == 1) {
            char c = str[0];
            if (c >= 'A' && c <= 'Z') return static_cast<WORD>(c);
            if (c >= 'a' && c <= 'z') return static_cast<WORD>(c - 'a' + 'A');
            if (c >= '0' && c <= '9') return static_cast<WORD>(c);
        }

        return VK_F9; // 默认值
    }
};

// 可配置UI实现
class ConfigurableHealBotUI {
private:
    HWND hwnd_;
    HWND process_list_;
    HWND refresh_button_;
    HWND start_button_;
    HWND stop_button_;
    HWND status_text_;
    HWND log_text_;

    // 治疗配置控件
    HWND config_group_;
    HWND normal_check_, normal_hp_edit_, normal_key_edit_;
    HWND enhanced_check_, enhanced_hp_edit_, enhanced_key_edit_;
    HWND emergency1_check_, emergency1_hp_edit_, emergency1_key_edit_;
    HWND emergency2_check_, emergency2_hp_edit_, emergency2_key_edit_;
    HWND sp_check_, sp_percent_edit_, sp_key_edit_;
    HWND skill_check_, skill_hp_edit_, skill_key_edit_, skill_cooldown_edit_;

    std::vector<ProcessInfo> processes_;
    std::unique_ptr<ConfigurableHealBot> heal_bot_;

    // 按键捕获状态
    HWND capturing_control_;  // 当前正在捕获按键的控件
    SimpleJSON config_;       // 配置数据
    bool loading_config_;     // 是否正在加载配置（防止触发OnConfigChanged）
    std::string config_file_path_;  // 配置文件的绝对路径

public:
    ConfigurableHealBotUI() : hwnd_(nullptr), capturing_control_(nullptr), loading_config_(false) {
        g_ui_instance = this;
        heal_bot_ = std::make_unique<ConfigurableHealBot>();

        // 初始化配置文件绝对路径
        char exePath[MAX_PATH];
        GetModuleFileNameA(nullptr, exePath, MAX_PATH);
        std::string exeDir = std::string(exePath);
        size_t lastSlash = exeDir.find_last_of("\\/");
        if (lastSlash != std::string::npos) {
            exeDir = exeDir.substr(0, lastSlash + 1);
        }
        config_file_path_ = exeDir + "heal_config.json";

        // 注意：这里不加载配置，等UI创建完成后再加载
    }

    bool CreateUI(HINSTANCE hInstance) {
        // 初始化通用控件库
        INITCOMMONCONTROLSEX icex;
        icex.dwSize = sizeof(INITCOMMONCONTROLSEX);
        icex.dwICC = ICC_WIN95_CLASSES | ICC_LISTVIEW_CLASSES;
        InitCommonControlsEx(&icex);

        WNDCLASSEX wc = { sizeof(WNDCLASSEX) };
        wc.lpfnWndProc = WindowProc;
        wc.hInstance = hInstance;
        wc.lpszClassName = L"ConfigurableHealBotUI";
        wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
        wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
        wc.hIcon = LoadIcon(nullptr, IDI_APPLICATION);

        if (!RegisterClassEx(&wc)) return false;

        hwnd_ = CreateWindowEx(
            0, L"ConfigurableHealBotUI", L"可配置加血机器人 - 工业级SPAM模式",
            WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 900, 700,
            nullptr, nullptr, hInstance, nullptr
        );

        if (!hwnd_) return false;

        CreateControls(hInstance);
        RefreshProcessList();

        // 在UI控件创建完成后加载配置
        LoadConfiguration();

        // 测试配置系统
        TestConfigSystem();

        LoadUIFromConfig();

        ShowWindow(hwnd_, SW_SHOW);
        UpdateWindow(hwnd_);

        return true;
    }

    void RunMessageLoop() {
        MSG msg;
        while (GetMessage(&msg, nullptr, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
    }

    void AppendLog(const std::string& message) {
        if (!log_text_) return;

        int length = GetWindowTextLength(log_text_);
        SendMessage(log_text_, EM_SETSEL, length, length);

        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);

        char timestamp[32];
        strftime(timestamp, sizeof(timestamp), "[%H:%M:%S] ", &timeinfo);

        std::string full_message = timestamp + message + "\r\n";
        SendMessageA(log_text_, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(full_message.c_str()));
        SendMessage(log_text_, WM_VSCROLL, SB_BOTTOM, 0);
    }

private:
    void CreateControls(HINSTANCE hInstance) {
        // 进程选择区域
        CreateWindow(L"STATIC", L"进程选择:",
            WS_CHILD | WS_VISIBLE, 10, 10, 100, 20,
            hwnd_, nullptr, hInstance, nullptr);

        process_list_ = CreateWindow(WC_LISTVIEW, L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | LVS_REPORT | LVS_SINGLESEL,
            10, 35, 860, 150, hwnd_, reinterpret_cast<HMENU>(IDC_PROCESS_LIST), hInstance, nullptr);

        // 设置进程列表列标题
        LVCOLUMN column = { 0 };
        column.mask = LVCF_TEXT | LVCF_WIDTH;

        column.pszText = const_cast<wchar_t*>(L"PID");
        column.cx = 80;
        ListView_InsertColumn(process_list_, 0, &column);

        column.pszText = const_cast<wchar_t*>(L"进程名");
        column.cx = 120;
        ListView_InsertColumn(process_list_, 1, &column);

        column.pszText = const_cast<wchar_t*>(L"启动时间");
        column.cx = 100;
        ListView_InsertColumn(process_list_, 2, &column);

        column.pszText = const_cast<wchar_t*>(L"窗口标题");
        column.cx = 300;
        ListView_InsertColumn(process_list_, 3, &column);

        column.pszText = const_cast<wchar_t*>(L"基地址");
        column.cx = 120;
        ListView_InsertColumn(process_list_, 4, &column);

        // 控制按钮
        refresh_button_ = CreateWindow(L"BUTTON", L"刷新列表",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 10, 195, 80, 30,
            hwnd_, reinterpret_cast<HMENU>(IDC_REFRESH_BUTTON), hInstance, nullptr);

        start_button_ = CreateWindow(L"BUTTON", L"开始治疗",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, 100, 195, 80, 30,
            hwnd_, reinterpret_cast<HMENU>(IDC_START_BUTTON), hInstance, nullptr);

        stop_button_ = CreateWindow(L"BUTTON", L"停止治疗",
            WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | WS_DISABLED, 190, 195, 80, 30,
            hwnd_, reinterpret_cast<HMENU>(IDC_STOP_BUTTON), hInstance, nullptr);

        // 治疗配置区域
        config_group_ = CreateWindow(L"BUTTON", L"治疗配置",
            WS_CHILD | WS_VISIBLE | BS_GROUPBOX, 10, 235, 860, 320,  // 高度从290增加到320
            hwnd_, reinterpret_cast<HMENU>(IDC_CONFIG_GROUP), hInstance, nullptr);

        // 创建配置控件 (使用网格布局)
        CreateConfigRow(hInstance, 0, L"普通治疗:", IDC_NORMAL_CHECK, IDC_NORMAL_HP_EDIT, IDC_NORMAL_KEY_EDIT,
            normal_check_, normal_hp_edit_, normal_key_edit_, L"浓缩黄金血药 - 优先级4");

        CreateConfigRow(hInstance, 1, L"增强治疗:", IDC_ENHANCED_CHECK, IDC_ENHANCED_HP_EDIT, IDC_ENHANCED_KEY_EDIT,
            enhanced_check_, enhanced_hp_edit_, enhanced_key_edit_, L"10%血药 - 优先级4");

        CreateConfigRow(hInstance, 2, L"紧急治疗1:", IDC_EMERGENCY1_CHECK, IDC_EMERGENCY1_HP_EDIT, IDC_EMERGENCY1_KEY_EDIT,
            emergency1_check_, emergency1_hp_edit_, emergency1_key_edit_, L"天地树树芽 - 优先级2");

        CreateConfigRow(hInstance, 3, L"紧急治疗2", IDC_EMERGENCY2_CHECK, IDC_EMERGENCY2_HP_EDIT, IDC_EMERGENCY2_KEY_EDIT,
            emergency2_check_, emergency2_hp_edit_, emergency2_key_edit_, L"天地树果实 - 优先级1");

        // 技能触发配置行（带冷却时间）- row 4
        CreateSkillConfigRow(hInstance, 4, L"技能触发:", IDC_SKILL_CHECK, IDC_SKILL_HP_EDIT,
            IDC_SKILL_KEY_EDIT, IDC_SKILL_COOLDOWN_EDIT,
            skill_check_, skill_hp_edit_, skill_key_edit_, skill_cooldown_edit_,
            L"低血量自动技能 - 优先级3");

        // SP恢复 - row 5（注意这里改成5了）
        CreateConfigRow(hInstance, 5, L"SP恢复:", IDC_SP_CHECK, IDC_SP_PERCENT_EDIT, IDC_SP_KEY_EDIT,
            sp_check_, sp_percent_edit_, sp_key_edit_, L"蓝药 - 优先级5");

        // 状态文本位置下移
        status_text_ = CreateWindow(L"STATIC", L"状态: 就绪 - 请选择进程并配置治疗设置",
            WS_CHILD | WS_VISIBLE, 10, 565, 860, 20,  // y从485改为565（6行*30+235+30）
            hwnd_, reinterpret_cast<HMENU>(IDC_STATUS_TEXT), hInstance, nullptr);

        // 日志文本框位置下移
        log_text_ = CreateWindow(L"EDIT", L"",
            WS_CHILD | WS_VISIBLE | WS_BORDER | WS_VSCROLL | ES_MULTILINE | ES_READONLY,
            10, 590, 860, 90, hwnd_, reinterpret_cast<HMENU>(IDC_LOG_TEXT), hInstance, nullptr);  // y从510改为590，高度调整为90
    }

    void CreateConfigRow(HINSTANCE hInstance, int row, const wchar_t* label,
        int check_id, int hp_id, int key_id,
        HWND& check_ctrl, HWND& hp_ctrl, HWND& key_ctrl,
        const wchar_t* description = nullptr) {  // 新增描述参数
        int y = 255 + row * 30;

        // 标签 - 调整位置给描述列留空间
        CreateWindow(L"STATIC", label,
            WS_CHILD | WS_VISIBLE, 25, y, 80, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 启用复选框
        check_ctrl = CreateWindow(L"BUTTON", L"启用",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 110, y, 50, 20,
            hwnd_, reinterpret_cast<HMENU>(check_id), hInstance, nullptr);

        // 血量/蓝量标签
         // 血量/蓝量标签 - 修改判断逻辑，row==5表示SP恢复
        CreateWindow(L"STATIC", row == 5 ? L"蓝量≤" : L"血量≤",
            WS_CHILD | WS_VISIBLE, 170, y, 50, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 血量/蓝量输入框
        hp_ctrl = CreateWindow(L"EDIT", L"95",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER, 220, y - 2, 40, 24,
            hwnd_, reinterpret_cast<HMENU>(hp_id), hInstance, nullptr);

        // 百分号标签
        CreateWindow(L"STATIC", L"%",
            WS_CHILD | WS_VISIBLE, 265, y, 20, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 按键标签
        CreateWindow(L"STATIC", L"按键:",
            WS_CHILD | WS_VISIBLE, 290, y, 40, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 按键输入框
        key_ctrl = CreateWindow(L"EDIT", L"F9",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 330, y - 2, 60, 24,
            hwnd_, reinterpret_cast<HMENU>(key_id), hInstance, nullptr);

        // 新增：描述列
        if (description) {
            CreateWindow(L"STATIC", description,
                WS_CHILD | WS_VISIBLE | SS_LEFT, 400, y, 200, 20,
                hwnd_, nullptr, hInstance, nullptr);
        }

        // 子类化按键输入框以捕获按键
        SetWindowSubclass(key_ctrl, KeyEditSubclassProc, 0, reinterpret_cast<DWORD_PTR>(this));
    }


    void CreateSkillConfigRow(HINSTANCE hInstance, int row, const wchar_t* label,
        int check_id, int hp_id, int key_id, int cooldown_id,
        HWND& check_ctrl, HWND& hp_ctrl, HWND& key_ctrl, HWND& cooldown_ctrl,
        const wchar_t* description = nullptr) {
        int y = 255 + row * 30;

        // 标签
        CreateWindow(L"STATIC", label,
            WS_CHILD | WS_VISIBLE, 25, y, 80, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 启用复选框
        check_ctrl = CreateWindow(L"BUTTON", L"启用",
            WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX, 110, y, 50, 20,
            hwnd_, reinterpret_cast<HMENU>(check_id), hInstance, nullptr);

        // 血量标签
        CreateWindow(L"STATIC", L"血量≤",
            WS_CHILD | WS_VISIBLE, 170, y, 50, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 血量输入框
        hp_ctrl = CreateWindow(L"EDIT", L"50",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER, 220, y - 2, 40, 24,
            hwnd_, reinterpret_cast<HMENU>(hp_id), hInstance, nullptr);

        // 百分号
        CreateWindow(L"STATIC", L"%",
            WS_CHILD | WS_VISIBLE, 265, y, 20, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 按键标签
        CreateWindow(L"STATIC", L"按键:",
            WS_CHILD | WS_VISIBLE, 290, y, 40, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 按键输入框
        key_ctrl = CreateWindow(L"EDIT", L"F6",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_READONLY, 330, y - 2, 60, 24,
            hwnd_, reinterpret_cast<HMENU>(key_id), hInstance, nullptr);

        // 冷却标签
        CreateWindow(L"STATIC", L"冷却:",
            WS_CHILD | WS_VISIBLE, 400, y, 40, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 冷却输入框
        cooldown_ctrl = CreateWindow(L"EDIT", L"5",
            WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER, 445, y - 2, 40, 24,
            hwnd_, reinterpret_cast<HMENU>(cooldown_id), hInstance, nullptr);

        // 秒标签
        CreateWindow(L"STATIC", L"秒",
            WS_CHILD | WS_VISIBLE, 490, y, 20, 20,
            hwnd_, nullptr, hInstance, nullptr);

        // 描述 - 调整位置，留出更多空间
        if (description) {
            CreateWindow(L"STATIC", description,
                WS_CHILD | WS_VISIBLE | SS_LEFT, 520, y, 330, 20,
                hwnd_, nullptr, hInstance, nullptr);
        }

        // 子类化按键输入框
        SetWindowSubclass(key_ctrl, KeyEditSubclassProc, 0, reinterpret_cast<DWORD_PTR>(this));
    }


    void RefreshProcessList() {
        ListView_DeleteAllItems(process_list_);
        processes_.clear();
        processes_ = ProcessScanner::ScanRagnarokProcesses();

        for (size_t i = 0; i < processes_.size(); ++i) {
            const auto& proc = processes_[i];

            LVITEM item = { 0 };
            item.mask = LVIF_TEXT;
            item.iItem = static_cast<int>(i);

            std::wstring pid_str = std::to_wstring(proc.pid);
            item.pszText = const_cast<wchar_t*>(pid_str.c_str());
            ListView_InsertItem(process_list_, &item);

            std::wstring name_str(proc.name.begin(), proc.name.end());
            ListView_SetItemText(process_list_, static_cast<int>(i), 1, const_cast<wchar_t*>(name_str.c_str()));

            std::wstring time_str(proc.start_time.begin(), proc.start_time.end());
            ListView_SetItemText(process_list_, static_cast<int>(i), 2, const_cast<wchar_t*>(time_str.c_str()));

            std::wstring title_str(proc.window_title.begin(), proc.window_title.end());
            ListView_SetItemText(process_list_, static_cast<int>(i), 3, const_cast<wchar_t*>(title_str.c_str()));

            std::wstringstream ss;
            ss << L"0x" << std::hex << std::uppercase << proc.base_address;
            std::wstring addr_str = ss.str();
            ListView_SetItemText(process_list_, static_cast<int>(i), 4, const_cast<wchar_t*>(addr_str.c_str()));
        }

        AppendLog("找到 " + std::to_string(processes_.size()) + " 个仙境传说进程");
    }

    void StartHealBot() {
        int selected = ListView_GetNextItem(process_list_, -1, LVNI_SELECTED);
        if (selected == -1) {
            MessageBox(hwnd_, L"请先选择一个进程.", L"未选择进程", MB_OK | MB_ICONWARNING);
            return;
        }

        if (selected >= 0 && selected < static_cast<int>(processes_.size())) {
            const auto& selected_process = processes_[selected];

            if (!selected_process.is_valid || !selected_process.handle) {
                MessageBox(hwnd_, L"选择的进程无效或无法访问.", L"进程无效", MB_OK | MB_ICONERROR);
                return;
            }

            // 更新机器人配置
            UpdateHealBotConfig();

            if (heal_bot_->StartWithProcess(selected_process)) {
                EnableWindow(start_button_, FALSE);
                EnableWindow(stop_button_, TRUE);
                EnableWindow(refresh_button_, FALSE);
                SetWindowText(status_text_, L"状态: 加血机器人运行中 - 可配置版本");
                AppendLog("加血机器人启动成功!");
            }
            else {
                MessageBox(hwnd_, L"启动加血机器人失败.", L"启动失败", MB_OK | MB_ICONERROR);
            }
        }
    }

    void StopHealBot() {
        AppendLog("停止按钮被点击 - 正在停止加血机器人...");

        // 立即禁用停止按钮防止重复点击
        EnableWindow(stop_button_, FALSE);
        SetWindowText(status_text_, L"状态: 正在停止...");

        // 在独立线程中停止以避免UI阻塞
        std::thread stop_thread([this]() {
            heal_bot_->Stop();

            // 通过消息更新UI
            PostMessage(hwnd_, WM_USER + 1, 0, 0);  // 自定义消息更新UI
            });
        stop_thread.detach();  // 让线程独立运行
    }

    // 改进的 OnConfigChanged 函数
    void OnConfigChanged() {
        // 如果正在加载配置，忽略这个事件
        if (loading_config_) {
            return;
        }

        static auto last_change_time = std::chrono::steady_clock::now();
        auto now = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(now - last_change_time).count();

        // 防抖：如果距离上次更改少于500ms，则忽略
        if (elapsed < 500) {
            return;
        }
        last_change_time = now;

        AppendLog("配置已更改，正在保存...");

        // 保存配置
        SaveConfiguration();

        // *** 关键修改：如果机器人正在运行，实时更新配置而不停止 ***
        if (heal_bot_->IsRunning()) {
            HealConfig normal, enhanced, emergency1, emergency2, sp, skill;  // 添加 skill 变量
            ReadConfigFromUI(normal, enhanced, emergency1, emergency2, sp, skill);

            // 实时更新配置
            heal_bot_->UpdateConfigRuntime(normal, enhanced, emergency1, emergency2, sp, skill);

            AppendLog("配置已实时更新，无需重新启动治疗!");
            SetWindowText(status_text_, L"状态: 配置已更新 - 加血机器人运行中");
        }
        else {
            AppendLog("配置已保存，下次启动时生效");
        }
    }

    void ApplyConfigToRunningBot() {
        if (!heal_bot_->IsRunning()) {
            return;
        }
        HealConfig normal, enhanced, emergency1, emergency2, sp, skill;
        ReadConfigFromUI(normal, enhanced, emergency1, emergency2, sp, skill);

        // 实时更新配置
        heal_bot_->UpdateConfigRuntime(normal, enhanced, emergency1, emergency2, sp, skill);

        AppendLog("运行时配置已应用!");
    }

    void OnKeyEditFocus(HWND edit_control) {
        capturing_control_ = edit_control;
        SetWindowTextA(edit_control, "按任意键...");
        AppendLog("等待按键输入...");
    }

    void OnKeyEditLostFocus(HWND edit_control) {
        if (capturing_control_ == edit_control) {
            capturing_control_ = nullptr;
        }
    }

    bool OnKeyCapture(WORD vk_code) {
        if (!capturing_control_) return false;

        // 忽略一些不适合的按键
        if (vk_code == VK_TAB || vk_code == VK_RETURN || vk_code == VK_ESCAPE) {
            // 这些按键用于界面导航，不用于游戏
            if (vk_code == VK_ESCAPE) {
                // ESC键取消捕获
                SetWindowTextA(capturing_control_, "F9");  // 恢复默认值
                capturing_control_ = nullptr;
            }
            return true;  // 仍然捕获这些按键，但不设置
        }

        std::string key_name = KeyNameConverter::VirtualKeyToString(vk_code);
        SetWindowTextA(capturing_control_, key_name.c_str());

        AppendLog("按键已设置: " + key_name);

        capturing_control_ = nullptr;

        // 触发配置更改
        OnConfigChanged();

        return true;
    }

    void UpdateHealBotConfig() {
        HealConfig normal, enhanced, emergency1, emergency2, sp, skill;

        // 读取UI配置
        ReadConfigFromUI(normal, enhanced, emergency1, emergency2, sp, skill);

        // 更新机器人配置
        heal_bot_->UpdateConfig(normal, enhanced, emergency1, emergency2, sp, skill);
    }

    void ReadConfigFromUI(HealConfig& normal, HealConfig& enhanced,
        HealConfig& emergency1, HealConfig& emergency2, HealConfig& sp, HealConfig& skill) {
        char buffer[256];

        // 普通治疗
        normal.enabled = SendMessage(normal_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(normal_hp_edit_, buffer, sizeof(buffer));
        normal.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(normal_key_edit_, buffer, sizeof(buffer));
        normal.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        normal.key_name = buffer;
        normal.description = "普通治疗";

        // 调试：显示从UI读取的值
        AppendLog("从UI读取 - normal_enabled: " + std::string(normal.enabled ? "是" : "否"));
        AppendLog("从UI读取 - normal_key: [" + normal.key_name + "]");

        // 增强治疗
        enhanced.enabled = SendMessage(enhanced_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(enhanced_hp_edit_, buffer, sizeof(buffer));
        enhanced.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(enhanced_key_edit_, buffer, sizeof(buffer));
        enhanced.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        enhanced.key_name = buffer;
        enhanced.description = "增强治疗";

        // 紧急治疗1
        emergency1.enabled = SendMessage(emergency1_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(emergency1_hp_edit_, buffer, sizeof(buffer));
        emergency1.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(emergency1_key_edit_, buffer, sizeof(buffer));
        emergency1.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        emergency1.key_name = buffer;
        emergency1.description = "紧急治疗1";

        // 紧急治疗2
        emergency2.enabled = SendMessage(emergency2_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(emergency2_hp_edit_, buffer, sizeof(buffer));
        emergency2.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(emergency2_key_edit_, buffer, sizeof(buffer));
        emergency2.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        emergency2.key_name = buffer;
        emergency2.description = "紧急治疗2";

        // 技能触发
        skill.enabled = SendMessage(skill_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(skill_hp_edit_, buffer, sizeof(buffer));
        skill.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(skill_key_edit_, buffer, sizeof(buffer));
        skill.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        skill.key_name = buffer;
        GetWindowTextA(skill_cooldown_edit_, buffer, sizeof(buffer));
        skill.cooldown_seconds = std::max(0, std::atoi(buffer));  // 确保非负
        skill.description = "技能触发";

        // SP恢复
        sp.enabled = SendMessage(sp_check_, BM_GETCHECK, 0, 0) == BST_CHECKED;
        GetWindowTextA(sp_percent_edit_, buffer, sizeof(buffer));
        sp.threshold = ValidatePercentage(std::atoi(buffer));
        GetWindowTextA(sp_key_edit_, buffer, sizeof(buffer));
        sp.key_code = KeyNameConverter::StringToVirtualKey(buffer);
        sp.key_name = buffer;
        sp.description = "SP恢复";
    }

    void TestConfigSystem() {
        AppendLog("=== 配置系统测试 ===");

        // 测试设置和获取
        config_.SetString("test_key", "test_value");
        config_.SetInt("test_int", 123);
        config_.SetBool("test_bool", true);

        std::string test_str = config_.GetString("test_key", "default");
        int test_int = config_.GetInt("test_int", 0);
        bool test_bool = config_.GetBool("test_bool", false);

        AppendLog("测试 - 字符串: " + test_str + " (期望: test_value)");
        AppendLog("测试 - 整数: " + std::to_string(test_int) + " (期望: 123)");
        AppendLog("测试 - 布尔: " + std::string(test_bool ? "true" : "false") + " (期望: true)");

        // 测试现有配置
        std::string normal_key_test = config_.GetString("normal_key", "NOT_FOUND");
        AppendLog("现有配置测试 - normal_key: [" + normal_key_test + "]");

        AppendLog("=== 配置系统测试完成 ===");
    }

    void LoadUIFromConfig() {
        AppendLog("开始应用配置到UI控件...");

        // 设置标志，防止UI更新触发配置保存
        loading_config_ = true;

        try {
            // 加载普通治疗配置
            bool normal_enabled = config_.GetBool("normal_enabled", true);
            int normal_threshold = config_.GetInt("normal_threshold", 95);
            std::string normal_key = config_.GetString("normal_key", "F9");

            AppendLog("应用配置 - 普通治疗: 启用=" + std::string(normal_enabled ? "是" : "否") +
                ", 阈值=" + std::to_string(normal_threshold) + ", 按键=" + normal_key);

            SendMessage(normal_check_, BM_SETCHECK, normal_enabled ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(normal_hp_edit_, std::to_string(ValidatePercentage(normal_threshold)).c_str());
            SetWindowTextA(normal_key_edit_, normal_key.c_str());

            // 加载增强治疗配置
            SendMessage(enhanced_check_, BM_SETCHECK, config_.GetBool("enhanced_enabled", true) ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(enhanced_hp_edit_, std::to_string(ValidatePercentage(config_.GetInt("enhanced_threshold", 95))).c_str());
            SetWindowTextA(enhanced_key_edit_, config_.GetString("enhanced_key", "F8").c_str());

            // 加载紧急治疗1配置
            SendMessage(emergency1_check_, BM_SETCHECK, config_.GetBool("emergency1_enabled", true) ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(emergency1_hp_edit_, std::to_string(ValidatePercentage(config_.GetInt("emergency1_threshold", 55))).c_str());
            SetWindowTextA(emergency1_key_edit_, config_.GetString("emergency1_key", "F7").c_str());

            // 加载紧急治疗2配置 - 特别关注
            bool emergency2_enabled = config_.GetBool("emergency2_enabled", true);
            int emergency2_threshold = ValidatePercentage(config_.GetInt("emergency2_threshold", 45));
            std::string emergency2_key = config_.GetString("emergency2_key", "F10");

            AppendLog("应用配置 - 紧急治疗2: 启用=" + std::string(emergency2_enabled ? "是" : "否") +
                ", 阈值=" + std::to_string(emergency2_threshold) + ", 按键=" + emergency2_key);

            SendMessage(emergency2_check_, BM_SETCHECK, emergency2_enabled ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(emergency2_hp_edit_, std::to_string(emergency2_threshold).c_str());
            SetWindowTextA(emergency2_key_edit_, emergency2_key.c_str());

            // 加载技能触发配置
            SendMessage(skill_check_, BM_SETCHECK, config_.GetBool("skill_enabled", false) ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(skill_hp_edit_, std::to_string(ValidatePercentage(config_.GetInt("skill_threshold", 50))).c_str());
            SetWindowTextA(skill_key_edit_, config_.GetString("skill_key", "F6").c_str());
            SetWindowTextA(skill_cooldown_edit_, std::to_string(config_.GetInt("skill_cooldown", 5)).c_str());


            // 加载SP恢复配置
            SendMessage(sp_check_, BM_SETCHECK, config_.GetBool("sp_enabled", true) ? BST_CHECKED : BST_UNCHECKED, 0);
            SetWindowTextA(sp_percent_edit_, std::to_string(ValidatePercentage(config_.GetInt("sp_threshold", 85))).c_str());
            SetWindowTextA(sp_key_edit_, config_.GetString("sp_key", "F8").c_str());

            AppendLog("UI配置应用完成");
        }
        catch (...) {
            AppendLog("UI配置应用过程中发生异常");
        }

        // 清除标志，重新允许配置保存
        loading_config_ = false;
    }
    void CreateDefaultConfig() {
        config_.SetBool("normal_enabled", true);
        config_.SetInt("normal_threshold", 95);
        config_.SetString("normal_key", "F9");

        config_.SetBool("enhanced_enabled", true);
        config_.SetInt("enhanced_threshold", 95);
        config_.SetString("enhanced_key", "F8");

        config_.SetBool("emergency1_enabled", true);
        config_.SetInt("emergency1_threshold", 55);
        config_.SetString("emergency1_key", "F7");

        config_.SetBool("emergency2_enabled", true);
        config_.SetInt("emergency2_threshold", 45);
        config_.SetString("emergency2_key", "F10");

        config_.SetBool("sp_enabled", true);
        config_.SetInt("sp_threshold", 85);
        config_.SetString("sp_key", "F8");

        config_.SetBool("skill_enabled", false);
        config_.SetInt("skill_threshold", 50);
        config_.SetString("skill_key", "F6");
        config_.SetInt("skill_cooldown", 5);
    }

    // 新增：验证加载的配置
    void ValidateLoadedConfig() {
        // 检查关键配置项是否存在，如果不存在则补充默认值
        if (config_.GetString("normal_key", "").empty()) {
            config_.SetString("normal_key", "F9");
            AppendLog("补充缺失的 normal_key 配置");
        }

        if (config_.GetString("emergency2_key", "").empty()) {
            config_.SetString("emergency2_key", "F10");
            AppendLog("补充缺失的 emergency2_key 配置");
        }

        // 验证阈值范围
        int normal_threshold = config_.GetInt("normal_threshold", 95);
        if (normal_threshold < 0 || normal_threshold > 99) {
            config_.SetInt("normal_threshold", 95);
            AppendLog("修正异常的 normal_threshold 值");
        }
    }

    // 新增：获取当前时间字符串用于备份文件名
    std::string GetCurrentTimeString() {
        auto now = std::chrono::system_clock::now();
        auto time_t = std::chrono::system_clock::to_time_t(now);
        struct tm timeinfo;
        localtime_s(&timeinfo, &time_t);

        char buffer[32];
        strftime(buffer, sizeof(buffer), "%Y%m%d_%H%M%S", &timeinfo);
        return std::string(buffer);
    }
    void LoadConfiguration() {
        AppendLog("配置文件路径: " + config_file_path_);

        // 首先检查文件是否存在
        std::ifstream checkFile(config_file_path_);
        bool fileExists = checkFile.is_open();
        if (fileExists) {
            checkFile.close();
        }

        if (!fileExists) {
            // 文件确实不存在，创建默认配置
            AppendLog("配置文件不存在，创建默认配置");
            CreateDefaultConfig();
            SaveConfiguration();
            AppendLog("默认配置文件已创建");
            return;
        }

        // 文件存在，尝试加载
        bool loadResult = config_.LoadFromFile(config_file_path_);
        AppendLog("配置加载结果: " + std::string(loadResult ? "成功" : "失败"));

        if (!loadResult) {
            // 文件存在但解析失败，不要覆盖！
            AppendLog("⚠️ 警告: 配置文件存在但解析失败，将尝试备份并重新创建");

            // 备份损坏的配置文件
            std::string backupPath = config_file_path_ + ".backup." + GetCurrentTimeString();
            if (CopyFileA(config_file_path_.c_str(), backupPath.c_str(), FALSE)) {
                AppendLog("已备份损坏的配置文件到: " + backupPath);
            }

            // 创建默认配置（但先尝试从备份中恢复一些设置）
            CreateDefaultConfig();
            SaveConfiguration();
            AppendLog("已重新创建配置文件，原文件已备份");
        }
        else {
            AppendLog("配置文件加载成功");
            ValidateLoadedConfig(); // 验证加载的配置
        }
    }


    void SaveConfiguration() {
        AppendLog("🚨 SaveConfiguration() 被调用！");

        HealConfig normal, enhanced, emergency1, emergency2, sp, skill;
        ReadConfigFromUI(normal, enhanced, emergency1, emergency2, sp, skill);

        config_.SetBool("normal_enabled", normal.enabled);
        config_.SetInt("normal_threshold", normal.threshold);
        config_.SetString("normal_key", normal.key_name);

        config_.SetBool("enhanced_enabled", enhanced.enabled);
        config_.SetInt("enhanced_threshold", enhanced.threshold);
        config_.SetString("enhanced_key", enhanced.key_name);

        config_.SetBool("emergency1_enabled", emergency1.enabled);
        config_.SetInt("emergency1_threshold", emergency1.threshold);
        config_.SetString("emergency1_key", emergency1.key_name);

        config_.SetBool("emergency2_enabled", emergency2.enabled);
        config_.SetInt("emergency2_threshold", emergency2.threshold);
        config_.SetString("emergency2_key", emergency2.key_name);

        config_.SetBool("sp_enabled", sp.enabled);
        config_.SetInt("sp_threshold", sp.threshold);
        config_.SetString("sp_key", sp.key_name);

        config_.SetBool("skill_enabled", skill.enabled);
        config_.SetInt("skill_threshold", skill.threshold);
        config_.SetString("skill_key", skill.key_name);
        config_.SetInt("skill_cooldown", skill.cooldown_seconds);

        if (config_.SaveToFile(config_file_path_)) {
            AppendLog("配置已保存到 " + config_file_path_);
            // 总是显示保存的配置（用于调试）
            AppendLog("保存配置 - 普通治疗按键: " + normal.key_name);
            AppendLog("保存配置 - 紧急治疗2按键: " + emergency2.key_name);
            AppendLog("保存配置 - 普通治疗阈值: " + std::to_string(normal.threshold));
        }
        else {
            AppendLog("保存配置失败!");
        }
    }

    int ValidatePercentage(int value) {
        if (value < 0) return 0;
        if (value > 99) return 99;
        return value;
    }

    // 子类化的按键输入框窗口过程
    static LRESULT CALLBACK KeyEditSubclassProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam,
        UINT_PTR uIdSubclass, DWORD_PTR dwRefData) {
        ConfigurableHealBotUI* ui = reinterpret_cast<ConfigurableHealBotUI*>(dwRefData);

        switch (uMsg) {
        case WM_SETFOCUS:
            ui->OnKeyEditFocus(hwnd);
            break;
        case WM_KILLFOCUS:
            ui->OnKeyEditLostFocus(hwnd);
            break;
        case WM_KEYDOWN:
            if (ui->OnKeyCapture(static_cast<WORD>(wParam))) {
                return 0; // 按键被捕获，停止处理
            }
            break;
        case WM_SYSKEYDOWN:
            // 捕获系统键（包括F10等）
            if (ui->OnKeyCapture(static_cast<WORD>(wParam))) {
                return 0; // 按键被捕获，停止处理
            }
            break;
        case WM_CHAR:
        case WM_SYSCHAR:
            // 阻止字符输入（我们只要按键捕获）
            if (ui->capturing_control_ == hwnd) {
                return 0;
            }
            break;
        }

        return DefSubclassProc(hwnd, uMsg, wParam, lParam);
    }

    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam) {
        if (!g_ui_instance) return DefWindowProc(hwnd, uMsg, wParam, lParam);

        switch (uMsg) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDC_APPLY_CONFIG_BUTTON:
                if (g_ui_instance->heal_bot_->IsRunning()) {
                    g_ui_instance->ApplyConfigToRunningBot();
                }
                else {
                    g_ui_instance->AppendLog("机器人未运行，配置将在下次启动时生效");
                }
                break;
            case IDC_REFRESH_BUTTON:
                g_ui_instance->RefreshProcessList();
                break;
            case IDC_START_BUTTON:
                g_ui_instance->StartHealBot();
                break;
            case IDC_STOP_BUTTON:
                g_ui_instance->StopHealBot();
                break;
            case IDC_NORMAL_CHECK:
            case IDC_ENHANCED_CHECK:
            case IDC_EMERGENCY1_CHECK:
            case IDC_EMERGENCY2_CHECK:
            case IDC_SP_CHECK:
            case IDC_NORMAL_HP_EDIT:
            case IDC_ENHANCED_HP_EDIT:
            case IDC_EMERGENCY1_HP_EDIT:
            case IDC_EMERGENCY2_HP_EDIT:
            case IDC_SP_PERCENT_EDIT:
                if (HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == BN_CLICKED) {
                    g_ui_instance->OnConfigChanged();
                }
                break;

            case IDC_SKILL_CHECK:
            case IDC_SKILL_HP_EDIT:
            case IDC_SKILL_COOLDOWN_EDIT:
                if (HIWORD(wParam) == EN_CHANGE || HIWORD(wParam) == BN_CLICKED) {
                    g_ui_instance->OnConfigChanged();
                }
                break;
            }

            break;

        case WM_USER + 1:  // 停止完成的自定义消息
            // 更新UI状态
            EnableWindow(g_ui_instance->start_button_, TRUE);
            EnableWindow(g_ui_instance->stop_button_, FALSE);
            EnableWindow(g_ui_instance->refresh_button_, TRUE);
            SetWindowText(g_ui_instance->status_text_, L"状态: 加血机器人已停止");
            g_ui_instance->AppendLog("加血机器人停止成功.");
            break;

        case WM_CLOSE:
            if (g_ui_instance->heal_bot_ && g_ui_instance->heal_bot_->IsRunning()) {
                // ⭐ 在独立线程中停止，避免UI线程阻塞
                g_ui_instance->AppendLog("正在停止机器人...");
                std::thread([hwnd]() {
                    g_ui_instance->heal_bot_->Stop();
                    // 停止完成后再关闭窗口
                    g_ui_instance->SaveConfiguration();
                    PostMessage(hwnd, WM_USER + 100, 0, 0);  // 发送自定义消息关闭窗口
                    }).detach();
            }
            else {
                // 没有运行中的机器人，直接关闭
                g_ui_instance->SaveConfiguration();
                g_ui_instance->AppendLog("程序关闭，配置已保存");
                DestroyWindow(hwnd);
            }
            break;

        case WM_USER + 100:  // 停止完成后的关闭消息
            g_ui_instance->AppendLog("程序关闭，配置已保存");
            DestroyWindow(hwnd);
            break;

        case WM_DESTROY:
            PostQuitMessage(0);
            break;

        default:
            return DefWindowProc(hwnd, uMsg, wParam, lParam);
        }

        return 0;
    }
};

// LogMessage函数实现（需要在ConfigurableHealBotUI类定义之后）
void LogMessage(const std::string& message) {
    if (g_ui_instance) {
        g_ui_instance->AppendLog(message);
    }
}

// 管理员权限管理
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID adminGroup = nullptr;

    SID_IDENTIFIER_AUTHORITY NtAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&NtAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &adminGroup)) {
        if (!CheckTokenMembership(nullptr, adminGroup, &isAdmin)) {
            isAdmin = FALSE;
        }
        FreeSid(adminGroup);
    }

    return isAdmin == TRUE;
}

bool RequestAdminRights() {
    if (IsRunningAsAdmin()) return true;

    wchar_t szPath[MAX_PATH];
    if (GetModuleFileName(nullptr, szPath, MAX_PATH) == 0) return false;

    SHELLEXECUTEINFO sei = { sizeof(sei) };
    sei.lpVerb = L"runas";
    sei.lpFile = szPath;
    sei.hwnd = nullptr;
    sei.nShow = SW_NORMAL;
    sei.fMask = SEE_MASK_FLAG_DDEWAIT | SEE_MASK_FLAG_NO_UI;

    if (ShellExecuteEx(&sei)) {
        ExitProcess(0);
    }
    return false;
}

// 主程序入口点
int main() {
    // ✅ 第一步：先检查管理员权限（避免重复验证）
    if (!IsRunningAsAdmin()) {
        if (!RequestAdminRights()) {
            MessageBox(nullptr, L"获取管理员权限失败.",
                L"权限提升失败", MB_OK | MB_ICONERROR);
            return -1;
        }
        return -1;  // 旧进程退出，等待新进程启动
    }

     //  ✅ 第二步：在确认是管理员模式后才进行授权验证 , 暂时移除验证
    //if (!SoftwareAuth::IsAuthorized()) {
       // if (!SoftwareAuth::ShowAuthDialog(nullptr)) {
          //  MessageBoxA(nullptr, "软件未授权，程序将退出", "授权验证失败", MB_OK | MB_ICONERROR);
          //  return -1;
       // }
   // }

    // 只有在确认有管理员权限后才创建UI和加载配置
    HINSTANCE hInstance = GetModuleHandle(nullptr);

    ConfigurableHealBotUI ui;
    if (!ui.CreateUI(hInstance)) {
        MessageBox(nullptr, L"创建UI失败", L"错误", MB_OK | MB_ICONERROR);
        return -1;
    }

    ui.RunMessageLoop();
    return 0;
}
