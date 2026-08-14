#ifndef PHISHING_DETECTOR_H
#define PHISHING_DETECTOR_H

#include <string>
#include <vector>

using namespace std;

class PhishingDetector
{
public:

    vector<string> extractURLs(
        const string& text
    );

    bool isIPAddress(
        const string& url
    );

    bool isShortenedURL(
        const string& url
    );

    bool hasSuspiciousDomain(
        const string& url
    );

    bool hasAtSymbol(
        const string& url
    );

    bool hasTooManySubdomains(
        const string& url
    );

    int calculatePhishingScore(
        const string& text
    );

    void displayAnalysis(
        const string& text
    );
};

#endif