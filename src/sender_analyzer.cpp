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
// EXTRACT DOMAIN
// ============================================================

string SenderAnalyzer::extractDomain(
    const string& email
)
{
    size_t at =
        email.find('@');


    if (at == string::npos)
    {
        return "";
    }


    if (at + 1 >= email.length())
    {
        return "";
    }


    string domain =
        email.substr(at + 1);


    return toLowerCase(domain);
}


// ============================================================
// EMAIL FORMAT
// ============================================================

bool SenderAnalyzer::isValidEmailFormat(
    const string& email
)
{
    regex pattern(
        R"(^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$)"
    );


    return regex_match(
        email,
        pattern
    );
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


    regex ipPattern(
        R"(^([0-9]{1,3}\.){3}[0-9]{1,3}$)"
    );


    return regex_match(
        domain,
        ipPattern
    );
}


// ============================================================
// SENDER RISK
// ============================================================

int SenderAnalyzer::calculateSenderRisk(
    const string& email
)
{
    int score = 0;


    if (!isValidEmailFormat(email))
    {
        score += 40;
    }


    string domain =
        extractDomain(email);


    if (domain.empty())
    {
        return 100;
    }


    if (hasIPAddress(email))
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
        cout << "Sender Risk      : 0/100\n";
        return;
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