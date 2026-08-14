#ifndef SCAN_REPORT_H
#define SCAN_REPORT_H

#include <string>
#include <vector>

using namespace std;

class ScanReport
{
public:

    static void saveReport(
        const string& sender,
        const string& subject,
        const string& classification,
        double mlProbability,
        int securityScore,
        int phishingScore,
        int senderRisk,
        double finalScore,
        const vector<string>& suspiciousWords,
        const vector<string>& urls,
        const vector<string>& keywords,
        const vector<string>& urgency,
        const vector<string>& security
    );
};

#endif