#include "phishing_detector.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <sstream>
#include <unordered_set>

using namespace std;


static string sanitizeText(const string& text)
{
    string result;

    for (char ch : text)
    {
        unsigned char c = static_cast<unsigned char>(ch);

        if (c == '\t' || (c >= 32 && c < 127))
        {
            result += ch;
        }
    }

    return result;
}


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

    string token;

    auto flush = [&](const string& raw) {

        if (raw.empty())
        {
            return;
        }

        string url = raw;

        while (
            !url.empty() &&
            (
                url.back() == '.' ||
                url.back() == ',' ||
                url.back() == '!' ||
                url.back() == '?' ||
                url.back() == ')' ||
                url.back() == ';'
            )
        )
        {
            url.pop_back();
        }

        if (url.empty())
        {
            return;
        }

        string lower =
            toLowerCase(url);

        bool isUrl = false;

        if (lower.rfind("http://", 0) == 0 ||
            lower.rfind("https://", 0) == 0 ||
            lower.rfind("www.", 0) == 0)
        {
            isUrl = true;
        }
        else
        {
            size_t slash =
                url.find('/');

            size_t dot =
                url.find('.');

            if (slash != string::npos &&
                dot != string::npos &&
                slash > dot)
            {
                isUrl = true;
            }
        }

        if (isUrl)
        {
            urls.push_back(url);
        }
    };

    for (char ch : text)
    {
        if (isspace(static_cast<unsigned char>(ch)))
        {
            flush(token);
            token.clear();
        }
        else
        {
            token += ch;
        }
    }

    flush(token);

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
    string host = url;

    size_t proto =
        host.find("://");

    if (proto != string::npos)
    {
        host =
            host.substr(proto + 3);
    }

    size_t slash =
        host.find('/');

    if (slash != string::npos)
    {
        host =
            host.substr(0, slash);
    }

    size_t colon =
        host.find(':');

    if (colon != string::npos)
    {
        host =
            host.substr(0, colon);
    }

    if (host.empty())
    {
        return false;
    }

    // Validate four octets manually.
    size_t pos = 0;

    for (int i = 0; i < 4; ++i)
    {
        size_t dot =
            host.find('.', pos);

        string octet;

        if (i < 3)
        {
            if (dot == string::npos)
            {
                return false;
            }

            octet =
                host.substr(pos, dot - pos);

            pos = dot + 1;
        }
        else
        {
            if (dot != string::npos)
            {
                return false;
            }

            octet =
                host.substr(pos);
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

    // Extract host for brand-legitimacy checks.
    string host = lower;

    size_t proto =
        host.find("://");

    if (proto != string::npos)
    {
        host =
            host.substr(proto + 3);
    }

    size_t slash =
        host.find('/');

    if (slash != string::npos)
    {
        host =
            host.substr(0, slash);
    }


    vector<string> brandWords =
    {
        "paypal",
        "microsoft",
        "google",
        "apple",
        "amazon",
        "instagram",
        "facebook"
    };

    vector<string> genericWords =
    {
        "login",
        "verify",
        "verification",
        "secure",
        "account",
        "update",
        "password",
        "bank",
        "wallet"
    };


    for (const string& word : genericWords)
    {
        if (lower.find(word) != string::npos)
        {
            return true;
        }
    }

    for (const string& brand : brandWords)
    {
        if (lower.find(brand) != string::npos &&
            host.find(brand) == string::npos)
        {
            // Brand name appears outside its own host -> spoofing.
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

    // Deduplicate URLs so a repeated link cannot inflate the score.
    vector<string> uniqueUrls;
    unordered_set<string> seen;

    for (const string& url : urls)
    {
        if (seen.insert(url).second)
        {
            uniqueUrls.push_back(url);
        }
    }

    urls = uniqueUrls;


    int score = 0;


    for (
        const string& url :
        urls
    )
    {
        if (score >= 100)
        {
            score = 100;
            break;
        }

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


    // Text-based phishing indicators (even without URLs).
    string lowerText =
        toLowerCase(text);

    vector<string> phishingPhrases = {
        "verify your account",
        "confirm your password",
        "click here",
        "account blocked",
        "login immediately",
        "update your information",
        "reset your password"
    };

    for (const string& phrase : phishingPhrases)
    {
        if (lowerText.find(phrase) != string::npos)
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

    // Deduplicate for display consistency with scoring.
    vector<string> uniqueUrls;
    unordered_set<string> seen;

    for (const string& url : urls)
    {
        if (seen.insert(url).second)
        {
            uniqueUrls.push_back(url);
        }
    }

    urls = uniqueUrls;


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
        cout << "Phishing Score   : "
             << score
             << "/100\n";
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
              << sanitizeText(urls[i])
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