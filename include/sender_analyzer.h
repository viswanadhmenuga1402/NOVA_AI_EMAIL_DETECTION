#ifndef SENDER_ANALYZER_H
#define SENDER_ANALYZER_H

#include <string>

using namespace std;

class SenderAnalyzer
{
public:

    string extractDomain(
        const string& email
    );

    bool isValidEmailFormat(
        const string& email
    );

    bool isFreeEmailProvider(
        const string& domain
    );

    bool isSuspiciousDomain(
        const string& domain
    );

    bool hasIPAddress(
        const string& email
    );

    int calculateSenderRisk(
        const string& email
    );

    void displayAnalysis(
        const string& email
    );
};

#endif