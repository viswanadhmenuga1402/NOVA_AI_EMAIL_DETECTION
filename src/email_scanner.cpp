#include "email_scanner.h"

#include <algorithm>
#include <cctype>
#include <iostream>
#include <regex>
#include <string>
#include <vector>

using namespace std;


// ============================================================
// Convert text to lowercase
// ============================================================

static string toLowerCase(
    const string& text
) {

    string result = text;

    transform(
        result.begin(),
        result.end(),
        result.begin(),
        [](unsigned char c) {
            return static_cast<char>(
                tolower(c)
            );
        }
    );

    return result;
}


// ============================================================
// Detect URLs
// ============================================================

vector<string> EmailScanner::detectURLs(
    const string& message
) {

    vector<string> results;

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
            results.push_back(url);
        }
    };

    for (char ch : message)
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

    return results;
}


// ============================================================
// Detect common spam keywords
// ============================================================

vector<string> EmailScanner::detectKeywords(
    const string& message
) {

    vector<string> found;

    string text =
        toLowerCase(message);


    vector<string> keywords = {

        "free",
        "winner",
        "won",
        "prize",
        "reward",
        "lottery",
        "bonus",
        "cash",
        "claim",
        "congratulations",
        "gift",
        "offer",
        "discount",
        "selected",
        "jackpot"

    };


    for (const string& word :
         keywords) {

        regex pattern(
            "\\b" + word + "\\b",
            regex_constants::icase
        );

        if (regex_search(text, pattern)) {

            found.push_back(word);
        }
    }


    return found;
}


// ============================================================
// Detect money-related patterns
// ============================================================

vector<string> EmailScanner::detectMoneyPatterns(
    const string& message
) {

    vector<string> found;

    string text =
        toLowerCase(message);


    vector<string> moneyPatterns = {

        "$",
        "₹",
        "rs",
        "inr",
        "usd",
        "dollar",
        "rupees",
        "money",
        "cash",
        "payment",
        "bank",
        "transfer"

    };


    for (const string& pattern :
         moneyPatterns) {

        bool isAlpha = !pattern.empty();

        for (char c : pattern)
        {
            if (!isalpha(static_cast<unsigned char>(c)))
            {
                isAlpha = false;
                break;
            }
        }

        bool matched = false;

        if (isAlpha)
        {
            regex wordPattern(
                "\\b" + pattern + "\\b",
                regex_constants::icase
            );

            matched =
                regex_search(text, wordPattern);
        }
        else
        {
            matched =
                text.find(pattern)
                != string::npos;
        }

        if (matched)
        {
            found.push_back(pattern);
        }
    }


    return found;
}


// ============================================================
// Detect urgency words
// ============================================================

vector<string> EmailScanner::detectUrgencyWords(
    const string& message
) {

    vector<string> found;

    string text =
        toLowerCase(message);


    vector<string> urgencyWords = {

        "urgent",
        "immediately",
        "now",
        "hurry",
        "limited",
        "expire",
        "expires",
        "today",
        "act now",
        "last chance",
        "within 24 hours",
        "quickly"

    };


    for (const string& word :
         urgencyWords) {

        bool matched = false;

        if (word.find(' ') != string::npos)
        {
            matched =
                text.find(word)
                != string::npos;
        }
        else
        {
            regex wordPattern(
                "\\b" + word + "\\b",
                regex_constants::icase
            );

            matched =
                regex_search(text, wordPattern);
        }

        if (matched)
        {
            found.push_back(word);
        }
    }


    return found;
}


// ============================================================
// Detect password / OTP / security requests
// ============================================================

vector<string> EmailScanner::detectSecurityRequests(
    const string& message
) {

    vector<string> found;

    string text =
        toLowerCase(message);


    vector<string> securityWords = {

        "password",
        "passcode",
        "otp",
        "one time password",
        "verification code",
        "security code",
        "pin",
        "cvv",
        "credit card",
        "debit card",
        "login",
        "verify your account"

    };


    for (const string& word :
         securityWords) {

        bool matched = false;

        if (word.find(' ') != string::npos)
        {
            matched =
                text.find(word)
                != string::npos;
        }
        else
        {
            regex wordPattern(
                "\\b" + word + "\\b",
                regex_constants::icase
            );

            matched =
                regex_search(text, wordPattern);
        }

        if (matched)
        {
            found.push_back(word);
        }
    }


    return found;
}


// ============================================================
// Detect excessive exclamation marks
// ============================================================

bool EmailScanner::hasExcessiveExclamation(
    const string& message
) {

    int count = 0;


    for (char ch : message) {

        if (ch == '!') {

            count++;
        }
    }


    return count >= 3;
}


// ============================================================
// Calculate rule-based risk score
// ============================================================

int EmailScanner::calculateRiskScore(
    const string& message
) {

    int score = 0;


    // URLs
    vector<string> urls =
        detectURLs(message);

    if (!urls.empty()) {

        score += 20;
    }


    // Spam keywords
    vector<string> keywords =
        detectKeywords(message);

    score +=
        static_cast<int>(
            keywords.size()
        ) * 5;


    // Money
    vector<string> money =
        detectMoneyPatterns(message);

    score +=
        static_cast<int>(
            money.size()
        ) * 5;


    // Urgency
    vector<string> urgency =
        detectUrgencyWords(message);

    score +=
        static_cast<int>(
            urgency.size()
        ) * 5;


    // Security requests
    vector<string> security =
        detectSecurityRequests(
            message
        );

    score +=
        static_cast<int>(
            security.size()
        ) * 10;


    // Excessive punctuation
    if (hasExcessiveExclamation(
            message)) {

        score += 10;
    }


    // Maximum score = 100
    if (score > 100) {

        score = 100;
    }


    return score;
}


// ============================================================
// Display complete scanner analysis
// ============================================================

void EmailScanner::analyze(
    const string& message
) {

    vector<string> urls =
        detectURLs(message);

    vector<string> keywords =
        detectKeywords(message);

    vector<string> money =
        detectMoneyPatterns(message);

    vector<string> urgency =
        detectUrgencyWords(message);

    vector<string> security =
        detectSecurityRequests(message);


    bool excessive =
        hasExcessiveExclamation(
            message
        );


    int riskScore =
        calculateRiskScore(message);


    cout << "\n============================================\n";
    cout << "          NOVA SECURITY SCANNER\n";
    cout << "============================================\n";


    cout << "\nRule-Based Risk Score : "
         << riskScore
         << "/100\n";


    cout << "\nSuspicious URLs:\n";

    if (urls.empty()) {

        cout << "  None\n";

    }
    else {

        for (const string& url :
             urls) {

            cout << "  - "
                 << url
                 << endl;
        }
    }


    cout << "\nSpam Keywords:\n";

    if (keywords.empty()) {

        cout << "  None\n";

    }
    else {

        for (const string& word :
             keywords) {

            cout << "  - "
                 << word
                 << endl;
        }
    }


    cout << "\nMoney Patterns:\n";

    if (money.empty()) {

        cout << "  None\n";

    }
    else {

        for (const string& item :
             money) {

            cout << "  - "
                 << item
                 << endl;
        }
    }


    cout << "\nUrgency Indicators:\n";

    if (urgency.empty()) {

        cout << "  None\n";

    }
    else {

        for (const string& item :
             urgency) {

            cout << "  - "
                 << item
                 << endl;
        }
    }


    cout << "\nSecurity Requests:\n";

    if (security.empty()) {

        cout << "  None\n";

    }
    else {

        for (const string& item :
             security) {

            cout << "  - "
                 << item
                 << endl;
        }
    }


    cout << "\nExcessive '!': ";

    if (excessive) {

        cout << "DETECTED\n";

    }
    else {

        cout << "No\n";
    }


    cout << "\nRisk Assessment: ";

    if (riskScore >= 70) {

        cout << "HIGH RISK\n";

    }
    else if (riskScore >= 40) {

        cout << "MEDIUM RISK\n";

    }
    else if (riskScore >= 20) {

        cout << "LOW RISK\n";

    }
    else {

        cout << "SAFE\n";
    }


    cout << "============================================\n";
}