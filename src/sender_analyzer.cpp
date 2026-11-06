#include "sender_analyzer.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <vector>

using namespace std;


// ============================================================
// Convert to lowercase
// ============================================================

static string toLowerCase(string text)
{
    transform(
        text.begin(),
        text.end(),
        text.begin(),
        [](unsigned char c)
        {
            return static_cast<char>(
                tolower(c)
            );
        }
    );

    return text;
}


// ============================================================
// TRIM HELPER
// ============================================================

static string trim(const string& text)
{
    size_t start = text.find_first_not_of(" \t\r\n");

    if (start == string::npos)
    {
        return "";
    }

    size_t end = text.find_last_not_of(" \t\r\n");

    return text.substr(start, end - start + 1);
}


// ============================================================
// EXTRACT DOMAIN
// ============================================================

string SenderAnalyzer::extractDomain(
    const string& email
)
{
    string trimmed =
        trim(email);

    size_t at =
        trimmed.find('@');


    if (at == string::npos)
    {
        return "";
    }


    if (at + 1 >= trimmed.length())
    {
        return "";
    }


    string domain =
        trimmed.substr(at + 1);


    return toLowerCase(domain);
}


// ============================================================
// EMAIL FORMAT
// ============================================================

bool SenderAnalyzer::isValidEmailFormat(
    const string& email
)
{
    string trimmed =
        trim(email);

    if (trimmed.empty() || trimmed.size() > 254)
    {
        return false;
    }

    size_t at =
        trimmed.find('@');

    if (at == string::npos ||
        at == 0 ||
        at == trimmed.size() - 1)
    {
        return false;
    }

    if (trimmed.find('@', at + 1) != string::npos)
    {
        return false;
    }

    string local =
        trimmed.substr(0, at);

    string domain =
        trimmed.substr(at + 1);

    if (local.empty() || domain.empty())
    {
        return false;
    }

    if (domain.find('.') == string::npos)
    {
        return false;
    }

    if (domain.front() == '.' ||
        domain.back() == '.' ||
        domain.front() == '-' ||
        domain.back() == '-')
    {
        return false;
    }

    size_t lastDot =
        domain.rfind('.');

    if (lastDot == string::npos ||
        lastDot == domain.size() - 1)
    {
        return false;
    }

    string tld =
        domain.substr(lastDot + 1);

    if (tld.size() < 2)
    {
        return false;
    }

    for (char c : tld)
    {
        if (!isalpha(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    for (char c : trimmed)
    {
        if (isspace(static_cast<unsigned char>(c)))
        {
            return false;
        }
    }

    return true;
}


// ============================================================
// FREE EMAIL PROVIDER
// ============================================================

bool SenderAnalyzer::isFreeEmailProvider(
    const string& domain
)
{
    string lower =
        toLowerCase(domain);


    vector<string> providers =
    {
        "gmail.com",
        "yahoo.com",
        "outlook.com",
        "hotmail.com",
        "live.com",
        "icloud.com",
        "proton.me",
        "protonmail.com"
    };


    for (
        const string& provider :
        providers
    )
    {
        if (lower == provider)
        {
            return true;
        }
    }


    return false;
}


// ============================================================
// SUSPICIOUS DOMAIN
// ============================================================

bool SenderAnalyzer::isSuspiciousDomain(
    const string& domain
)
{
    string lower =
        toLowerCase(domain);


    vector<string> suspiciousWords =
    {
        "secure",
        "verify",
        "verification",
        "account",
        "login",
        "support",
        "update",
        "password",
        "payment",
        "bank",
        "wallet",
        "security"
    };


    for (
        const string& word :
        suspiciousWords
    )
    {
        if (
            lower.find(word)
            != string::npos
        )
        {
            return true;
        }
    }


    return false;
}


// ============================================================
// IP ADDRESS
// ============================================================

bool SenderAnalyzer::hasIPAddress(
    const string& email
)
{
    string domain =
        extractDomain(email);


    if (domain.empty())
    {
        return false;
    }

    // Validate four octets manually (linear, ReDoS-safe).
    size_t pos = 0;

    for (int i = 0; i < 4; ++i)
    {
        size_t dot =
            domain.find('.', pos);

        string octet;

        if (i < 3)
        {
            if (dot == string::npos)
            {
                return false;
            }

            octet =
                domain.substr(pos, dot - pos);

            pos = dot + 1;
        }
        else
        {
            if (dot != string::npos)
            {
                return false;
            }

            octet =
                domain.substr(pos);
        }

        if (octet.empty() || octet.size() > 3)
        {
            return false;
        }

        for (char c : octet)
        {
            if (!isdigit(static_cast<unsigned char>(c)))
            {
                return false;
            }
        }

        int value =
            stoi(octet);

        if (value < 0 || value > 255)
        {
            return false;
        }
    }

    return true;
}


// ============================================================
// SENDER RISK
// ============================================================

int SenderAnalyzer::calculateSenderRisk(
    const string& email
)
{
    string trimmed =
        trim(email);

    int score = 0;


    if (!isValidEmailFormat(trimmed))
    {
        score += 40;
    }


    string domain =
        extractDomain(trimmed);


    if (domain.empty())
    {
        return 100;
    }


    if (hasIPAddress(trimmed))
    {
        score += 40;
    }


    if (isSuspiciousDomain(domain))
    {
        score += 20;
    }


    // Very long domain
    if (domain.length() > 40)
    {
        score += 10;
    }


    // Excessive subdomains
    int dots = 0;

    for (char c : domain)
    {
        if (c == '.')
        {
            dots++;
        }
    }


    if (dots >= 3)
    {
        score += 15;
    }


    if (score > 100)
    {
        score = 100;
    }


    return score;
}


// ============================================================
// DISPLAY ANALYSIS
// ============================================================

void SenderAnalyzer::displayAnalysis(
    const string& email
)
{
    cout << "\n";
    cout << "---------- SENDER ANALYSIS ----------------\n";


    if (email.empty())
    {
        cout << "Sender           : Not provided\n";
    }


    string domain =
        extractDomain(email);


    cout << "Sender           : "
         << email
         << "\n";


    cout << "Domain           : ";


    if (domain.empty())
    {
        cout << "Invalid";
    }
    else
    {
        cout << domain;
    }

    cout << "\n";


    cout << "Valid Format     : "
         << (
                isValidEmailFormat(email)
                ? "YES"
                : "NO"
            )
         << "\n";


    cout << "Free Provider    : "
         << (
                isFreeEmailProvider(domain)
                ? "YES"
                : "NO"
            )
         << "\n";


    cout << "Suspicious Domain: "
         << (
                isSuspiciousDomain(domain)
                ? "YES"
                : "NO"
            )
         << "\n";


    cout << "IP Address       : "
         << (
                hasIPAddress(email)
                ? "YES"
                : "NO"
            )
         << "\n";


    int risk =
        calculateSenderRisk(email);


    cout << "Sender Risk      : "
         << risk
         << "/100\n";


    if (risk >= 70)
    {
        cout << "Sender Status    : HIGH RISK\n";
    }
    else if (risk >= 40)
    {
        cout << "Sender Status    : SUSPICIOUS\n";
    }
    else
    {
        cout << "Sender Status    : LOW RISK\n";
    }
}