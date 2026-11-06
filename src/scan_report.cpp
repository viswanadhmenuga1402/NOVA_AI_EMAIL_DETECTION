
#include "scan_report.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <ctime>

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


void ScanReport::saveReport(
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
)
{
    ofstream file(
        "latest_scan_report.txt"
    );


    if (!file.is_open())
    {
        cout << "\nCould not create scan report.\n";
        return;
    }


    time_t currentTime =
        time(nullptr);

    char* timeString =
        ctime(&currentTime);

    file << "============================================\n";
    file << "              NOVA AI REPORT\n";
    file << "============================================\n\n";


    file << "Sender        : "
         << sanitizeText(sender)
         << "\n";


    file << "Subject       : "
         << sanitizeText(subject)
         << "\n";


    file << "Classification : "
         << classification
         << "\n\n";


    file << "--------------- AI ANALYSIS ----------------\n";


    file << fixed
         << setprecision(2);


    file << "ML Probability : "
         << mlProbability
         << "%\n";


    file << "Security Score : "
         << securityScore
         << "/100\n";


    file << "Phishing Score : "
         << phishingScore
         << "/100\n";


    file << "Sender Risk    : "
         << senderRisk
         << "/100\n";


    file << "Final Risk     : "
         << finalScore
         << "%\n\n";


    file << "------------- SUSPICIOUS WORDS -------------\n";


    for (const string& word : suspiciousWords)
    {
        file << "- "
             << sanitizeText(word)
             << "\n";
    }


    file << "\n------------------ URLS --------------------\n";


    for (const string& url : urls)
    {
        file << "- "
             << sanitizeText(url)
             << "\n";
    }


    file << "\n-------------- SPAM KEYWORDS ---------------\n";


    for (const string& keyword : keywords)
    {
        file << "- "
             << sanitizeText(keyword)
             << "\n";
    }


    file << "\n------------- URGENCY INDICATORS -----------\n";


    for (const string& word : urgency)
    {
        file << "- "
             << sanitizeText(word)
             << "\n";
    }


    file << "\n------------- SECURITY REQUESTS ------------\n";


    for (const string& request : security)
    {
        file << "- "
             << sanitizeText(request)
             << "\n";
    }


    file << "\n============================================\n";


    file << "Generated: ";

    if (timeString != nullptr)
    {
        file << timeString;
    }
    else
    {
        file << "Unknown time\n";
    }


    file << "============================================\n";


    file.close();


    cout << "\nDetailed report saved to:\n";
    cout << "latest_scan_report.txt\n";
}