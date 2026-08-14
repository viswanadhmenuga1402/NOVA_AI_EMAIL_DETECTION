 
#ifndef EMAIL_SCANNER_H
#define EMAIL_SCANNER_H

#include <string>
#include <vector>

using namespace std;

class EmailScanner {

public:

    // Detect suspicious URLs
    vector<string> detectURLs(
        const string& message
    );

    // Detect suspicious keywords
    vector<string> detectKeywords(
        const string& message
    );

    // Detect money-related content
    vector<string> detectMoneyPatterns(
        const string& message
    );

    // Detect urgency-related words
    vector<string> detectUrgencyWords(
        const string& message
    );

    // Detect OTP/password requests
    vector<string> detectSecurityRequests(
        const string& message
    );

    // Detect excessive punctuation
    bool hasExcessiveExclamation(
        const string& message
    );

    // Calculate rule-based risk score
    int calculateRiskScore(
        const string& message
    );

    // Display complete scanner result
    void analyze(
        const string& message
    );
};

#endif