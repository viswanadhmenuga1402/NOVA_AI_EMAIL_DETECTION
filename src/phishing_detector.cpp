#include "phishing_detector.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <sstream>

using namespace std;


// ============================================================
// Convert string to lowercase
// ============================================================

static string toLowerCase(
    string text
)
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
// EXTRACT URLs
// ============================================================

vector<string>
PhishingDetector::extractURLs(
    const string& text
)
{
    vector<string> urls;


    regex urlPattern(
        R"((https?://[^\s]+|www\.[^\s]+))",
        regex::icase
    );


    sregex_iterator begin(
        text.begin(),
        text.end(),
        urlPattern
    );


    sregex_iterator end;


    for (
        sregex_iterator i = begin;
        i != end;
        ++i
    )
    {
        string url =
            (*i).str();


        // Remove common punctuation
        while (
            !url.empty() &&
            (
                url.back() == '.' ||
                url.back() == ',' ||
                url.back() == '!' ||
                url.back() == '?' ||
                url.back() == ')' 
            )
        )
        {
            url.pop_back();
        }


        urls.push_back(url);
    }


    return urls;
}


// ============================================================
// IP ADDRESS URL
// ============================================================

bool
PhishingDetector::isIPAddress(
    const string& url
)
{
    regex ipPattern(
        R"(https?://([0-9]{1,3}\.){3}[0-9]{1,3})",
        regex::icase
    );


    return regex_search(
        url,
        ipPattern
    );
}


// ============================================================
// URL SHORTENER
// ============================================================

bool
PhishingDetector::isShortenedURL(
    const string& url
)
{
    string lower =
        toLowerCase(url);


    vector<string> shorteners =
    {
        "bit.ly",
        "tinyurl.com",
        "t.co",
        "goo.gl",
        "is.gd",
        "ow.ly",
        "buff.ly",
        "cutt.ly",
        "shorturl.at"
    };


    for (
        const string& domain :
        shorteners
    )
    {
        if (
            lower.find(domain)
            != string::npos
        )
        {
            return true;
        }
    }


    return false;
}


// ============================================================
// SUSPICIOUS DOMAIN
// ============================================================

bool
PhishingDetector::hasSuspiciousDomain(
    const string& url
)
{
    string lower =
        toLowerCase(url);


    vector<string> suspiciousWords =
    {
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "wallet",
        "paypal",
        "microsoft",
        "google",
        "apple",
        "amazon",
        "instagram",
        "facebook"
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
// @ SYMBOL
// ============================================================

bool
PhishingDetector::hasAtSymbol(
    const string& url
)
{
    return url.find('@')
           != string::npos;
}


// ============================================================
// TOO MANY SUBDOMAINS
// ============================================================

bool
PhishingDetector::hasTooManySubdomains(
    const string& url
)
{
    string lower =
        toLowerCase(url);


    size_t protocol =
        lower.find("://");


    string domain;


    if (protocol != string::npos)
    {
        domain =
            lower.substr(
                protocol + 3
            );
    }
    else
    {
        domain = lower;
    }


    size_t slash =
        domain.find('/');


    if (slash != string::npos)
    {
        domain =
            domain.substr(
                0,
                slash
            );
    }


    int dots = 0;


    for (char c : domain)
    {
        if (c == '.')
        {
            dots++;
        }
    }


    return dots >= 3;
}


// ============================================================
// PHISHING SCORE
// ============================================================

int
PhishingDetector::calculatePhishingScore(
    const string& text
)
{
    vector<string> urls =
        extractURLs(text);


    if (urls.empty())
    {
        return 0;
    }


    int score = 0;


    for (
        const string& url :
        urls
    )
    {
        if (isIPAddress(url))
        {
            score += 30;
        }


        if (isShortenedURL(url))
        {
            score += 15;
        }


        if (hasSuspiciousDomain(url))
        {
            score += 15;
        }


        if (hasAtSymbol(url))
        {
            score += 20;
        }


        if (hasTooManySubdomains(url))
        {
            score += 15;
        }


        string lower =
            toLowerCase(url);


        if (
            lower.find("http://")
            != string::npos
        )
        {
            score += 10;
        }
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

void
PhishingDetector::displayAnalysis(
    const string& text
)
{
    vector<string> urls =
        extractURLs(text);


    int score =
        calculatePhishingScore(text);


    cout << "\n";
    cout << "---------- PHISHING ANALYSIS --------------\n";


    cout << "URLs Detected    : "
         << urls.size()
         << "\n";


    if (urls.empty())
    {
        cout << "URL Risk         : None\n";
        cout << "Phishing Score   : 0/100\n";
        return;
    }


    for (
        size_t i = 0;
        i < urls.size();
        i++
    )
    {
        cout << "\nURL "
             << i + 1
             << " : "
             << urls[i]
             << "\n";


        cout << "  IP Address     : "
             << (
                    isIPAddress(urls[i])
                    ? "YES"
                    : "NO"
                )
             << "\n";


        cout << "  URL Shortener  : "
             << (
                    isShortenedURL(urls[i])
                    ? "YES"
                    : "NO"
                )
             << "\n";


        cout << "  Suspicious Dom.: "
             << (
                    hasSuspiciousDomain(urls[i])
                    ? "YES"
                    : "NO"
                )
             << "\n";


        cout << "  @ Symbol       : "
             << (
                    hasAtSymbol(urls[i])
                    ? "YES"
                    : "NO"
                )
             << "\n";


        cout << "  Many Subdomain : "
             << (
                    hasTooManySubdomains(urls[i])
                    ? "YES"
                    : "NO"
                )
             << "\n";
    }


    cout << "\nPhishing Score   : "
         << score
         << "/100\n";


    if (score >= 70)
    {
        cout << "URL Risk         : HIGH\n";
    }
    else if (score >= 40)
    {
        cout << "URL Risk         : MEDIUM\n";
    }
    else
    {
        cout << "URL Risk         : LOW\n";
    }
}