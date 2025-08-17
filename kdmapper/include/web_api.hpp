#pragma once
#include <string>
#include <Windows.h>
#include <array>
#include <regex>

namespace Web
{
    inline bool CheckConnection()
    {
        int result = system("ping google.com > nul");
        if (result == 0)
            return true;
        else
            return false;
    }

    inline bool Get(std::string url, std::string& response)
    {
        response = "";
        std::string cmd = "curl -s -X GET " + url;

        std::array<char, 128> buffer;
        std::unique_ptr<FILE, decltype(&_pclose)> pipe(_popen(cmd.c_str(), "r"), _pclose);

        if (!pipe)
        {
            return false;
        }
        while (fgets(buffer.data(), static_cast<int>(buffer.size()), pipe.get()) != nullptr)
        {
            response += buffer.data();
        }

        std::regex pattern("\\d{3}:");
        if (std::regex_search(response, pattern))
        {
            return false;
        }

        return true;
    }

    inline bool Post(std::string url, std::string& params)
    {
        return true;
    }
}