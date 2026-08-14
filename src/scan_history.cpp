#include "scan_history.h"

#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>

using namespace std;


// ============================================================
// CONSTRUCTOR
// ============================================================

ScanHistory::ScanHistory()
{
    loadHistory();
}


// ============================================================
// LOAD HISTORY
// ============================================================

void ScanHistory::loadHistory()
{
    records.clear();

    ifstream file("scan_history.txt");

    if (!file.is_open())
    {
        return;
    }


    string line;


    // Skip header/separator lines.
    while (getline(file, line))
    {
        if (line.empty())
        {
            continue;
        }

        if (line.find("SCAN HISTORY") != string::npos)
        {
            continue;
        }

        if (line.find("ID") == 0)
        {
            continue;
        }

        if (line.find("---") != string::npos)
        {
            continue;
        }


        stringstream ss(line);

        int id;
        string classification;
        double ml;
        int security;
        double finalScore;


        if (
            ss >> id
            >> classification
            >> ml
            >> security
            >> finalScore
        )
        {
            ScanRecord record;

            record.id = id;
            record.classification = classification;
            record.mlProbability = ml;
            record.securityScore = security;
            record.finalScore = finalScore;

            records.push_back(record);
        }
    }


    file.close();
}


// ============================================================
// SAVE TO FILE
// ============================================================

void ScanHistory::saveToFile()
{
    ofstream file(
        "scan_history.txt"
    );


    if (!file.is_open())
    {
        cout << "\nUnable to save scan history.\n";
        return;
    }


    file << "==============================================================\n";
    file << "                    SCAN HISTORY\n";
    file << "==============================================================\n";

    file << left
         << setw(6) << "ID"
         << setw(18) << "Classification"
         << setw(12) << "ML"
         << setw(12) << "Security"
         << setw(12) << "Final"
         << "\n";

    file << "--------------------------------------------------------------\n";


    file << fixed
         << setprecision(2);


    for (const ScanRecord& record : records)
    {
        file << left
             << setw(6) << record.id
             << setw(18) << record.classification
             << setw(12) << record.mlProbability
             << setw(12) << record.securityScore
             << setw(12) << record.finalScore
             << "\n";
    }


    file << "==============================================================\n";


    file.close();
}


// ============================================================
// SAVE SCAN
// ============================================================

void ScanHistory::saveScan(
    const string& email,
    const string& classification,
    double mlProbability,
    int securityScore,
    double finalScore
)
{
    ScanRecord record;


    record.id =
        static_cast<int>(records.size()) + 1;


    record.classification =
        classification;


    record.mlProbability =
        mlProbability;


    record.securityScore =
        securityScore;


    record.finalScore =
        finalScore;


    records.push_back(record);


    saveToFile();
}


// ============================================================
// DISPLAY HISTORY
// ============================================================

void ScanHistory::displayHistory()
{
    loadHistory();


    cout << "\n";
    cout << "==============================================================\n";
    cout << "                    SCAN HISTORY\n";
    cout << "==============================================================\n";


    if (records.empty())
    {
        cout << "\nNo scan history available.\n";

        cout << "==============================================================\n";

        return;
    }


    cout << left
         << setw(6) << "ID"
         << setw(18) << "Classification"
         << setw(12) << "ML"
         << setw(12) << "Security"
         << setw(12) << "Final"
         << "\n";


    cout << "--------------------------------------------------------------\n";


    cout << fixed
         << setprecision(2);


    for (const ScanRecord& record : records)
    {
        cout << left
             << setw(6) << record.id
             << setw(18) << record.classification
             << setw(12) << record.mlProbability
             << setw(12) << record.securityScore
             << setw(12) << record.finalScore
             << "\n";
    }


    cout << "==============================================================\n";

    cout << "\nSaved file: scan_history.txt\n";
}


// ============================================================
// GET TOTAL
// ============================================================

int ScanHistory::getTotalScans() const
{
    return static_cast<int>(
        records.size()
    );
}


// ============================================================
// GET SPAM COUNT
// ============================================================

int ScanHistory::getSpamCount() const
{
    int count = 0;


    for (const ScanRecord& record : records)
    {
        if (
            record.classification == "SPAM"
        )
        {
            count++;
        }
    }


    return count;
}


// ============================================================
// GET SUSPICIOUS COUNT
// ============================================================

int ScanHistory::getSuspiciousCount() const
{
    int count = 0;


    for (const ScanRecord& record : records)
    {
        if (
            record.classification == "SUSPICIOUS"
        )
        {
            count++;
        }
    }


    return count;
}


// ============================================================
// GET HAM COUNT
// ============================================================

int ScanHistory::getHamCount() const
{
    int count = 0;


    for (const ScanRecord& record : records)
    {
        if (
            record.classification == "HAM"
        )
        {
            count++;
        }
    }


    return count;
}


// ============================================================
// DISPLAY STATISTICS
// ============================================================

void ScanHistory::displayStatistics()
{
    loadHistory();


    int total =
        getTotalScans();


    int spam =
        getSpamCount();


    int suspicious =
        getSuspiciousCount();


    int ham =
        getHamCount();


    double spamRate = 0.0;

    double suspiciousRate = 0.0;

    double hamRate = 0.0;


    if (total > 0)
    {
        spamRate =
            (static_cast<double>(spam) / total) * 100.0;


        suspiciousRate =
            (static_cast<double>(suspicious) / total) * 100.0;


        hamRate =
            (static_cast<double>(ham) / total) * 100.0;
    }


    cout << "\n";
    cout << "============================================\n";
    cout << "              SCAN STATISTICS\n";
    cout << "============================================\n\n";


    cout << "Total Scans       : "
         << total
         << "\n";


    cout << "Spam Emails       : "
         << spam
         << "\n";


    cout << "Suspicious Emails : "
         << suspicious
         << "\n";


    cout << "Safe Emails       : "
         << ham
         << "\n\n";


    cout << fixed
         << setprecision(2);


    cout << "Spam Detection Rate : "
         << spamRate
         << "%\n";


    cout << "Suspicious Rate     : "
         << suspiciousRate
         << "%\n";


    cout << "Safe Rate           : "
         << hamRate
         << "%\n";


    cout << "============================================\n";
}


// ============================================================
// CLEAR HISTORY
// ============================================================

void ScanHistory::clearHistory()
{
    records.clear();


    ofstream file(
        "scan_history.txt",
        ios::trunc
    );


    if (file.is_open())
    {
        file.close();
    }


    cout << "\n";
    cout << "Scan history cleared successfully.\n";
}