#ifndef SCAN_HISTORY_H
#define SCAN_HISTORY_H

#include <string>
#include <vector>

using namespace std;


// ============================================================
// SCAN RECORD
// ============================================================

struct ScanRecord
{
    int id;

    string classification;

    double mlProbability;

    int securityScore;

    double finalScore;
};


// ============================================================
// SCAN HISTORY
// ============================================================

class ScanHistory
{
private:

    vector<ScanRecord> records;


    void loadHistory();

    void saveToFile();


public:

    ScanHistory();


    void saveScan(
        const string& email,
        const string& classification,
        double mlProbability,
        int securityScore,
        double finalScore
    );


    void displayHistory();

    void displayStatistics();

    void clearHistory();


    int getTotalScans() const;

    int getSpamCount() const;

    int getSuspiciousCount() const;

    int getHamCount() const;
};

#endif