#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include "naive_bayes.h"
#include "email_scanner.h"
#include "scan_history.h"
#include "email.h"
#include "phishing_detector.h"
#include "sender_analyzer.h"
#include "explanation_engine.h"
#include "scan_report.h"

using namespace std;


// ============================================================
// PRINT LIST
// ============================================================

void printList(const vector<string>& items)
{
    if (items.empty())
    {
        cout << "None";
        return;
    }

    for (size_t i = 0; i < items.size(); ++i)
    {
        cout << items[i];

        if (i + 1 < items.size())
            cout << ", ";
    }
}


// ============================================================
// SANITIZE TEXT (remove control characters)
// ============================================================

string sanitizeText(const string& text)
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
// LATEST REPORT
// ============================================================

void viewLatestReport()
{
    ifstream file("latest_scan_report.txt");

    cout << "\n";
    cout << "============================================================\n";
    cout << "                    LATEST SCAN REPORT\n";
    cout << "============================================================\n";

    if (!file.is_open())
    {
        cout << "\nNo report available.\n";
        cout << "Please scan an email first.\n";
        cout << "============================================================\n";
        return;
    }

    string line;

    while (getline(file, line))
    {
        cout << line << '\n';
    }

    file.close();

    cout << "============================================================\n";
}


// ============================================================
// SCAN EMAIL
// ============================================================

void scanEmail(
    NaiveBayes& model,
    EmailScanner& scanner,
    ScanHistory& history
)
{
    Email email;

    PhishingDetector phishing;
    SenderAnalyzer senderAnalyzer;
    ExplanationEngine explanation;


    cout << "\n";
    cout << "============================================\n";
    cout << "              NOVA EMAIL SCANNER\n";
    cout << "============================================\n";


    // ========================================================
    // SENDER
    // ========================================================

    cout << "\nSender:\n> ";
    getline(cin, email.sender);


    // ========================================================
    // SUBJECT
    // ========================================================

    cout << "\nSubject:\n> ";
    getline(cin, email.subject);


    // ========================================================
    // MULTI-LINE BODY
    // ========================================================

    cout << "\nBody:\n";
    cout << "(Type END on a separate line when finished)\n";

    email.body.clear();

    string bodyLine;

    while (true)
    {
        cout << "> ";

        if (!getline(cin, bodyLine))
        {
            break;
        }

        if (bodyLine == "END")
            break;

        if (email.body.size() + bodyLine.size() + 1 > 1000000)
        {
            cout << "\nEmail input is too large.\n";
            return;
        }

        email.body += bodyLine;
        email.body += "\n";
    }


    // ========================================================
    // EMPTY EMAIL CHECK
    // ========================================================

    auto isEmptyOrWhitespace = [](const string& value) {
        return value.find_first_not_of(" \t\r\n") == string::npos;
    };

    if (email.sender.size() > 100000 ||
        email.subject.size() > 100000 ||
        email.body.size() > 1000000)
    {
        cout << "\nEmail input is too large.\n";
        return;
    }

    if (
        isEmptyOrWhitespace(email.sender) &&
        isEmptyOrWhitespace(email.subject) &&
        isEmptyOrWhitespace(email.body)
    )
    {
        cout << "\nEmail cannot be empty.\n";
        return;
    }


    // ========================================================
    // COMPLETE EMAIL
    // ========================================================

    string fullEmail =
        email.getFullText();


    // ========================================================
    // SENDER ANALYSIS
    // ========================================================

    int senderRisk =
        senderAnalyzer.calculateSenderRisk(
            email.sender
        );


    // ========================================================
    // NAIVE BAYES
    // ========================================================

    double mlProbability =
        model.getSpamProbability(
            fullEmail
        );

    string mlPrediction =
        model.predict(
            fullEmail
        );

    string confidence =
        model.getConfidence(
            mlProbability
        );

    string mlRisk =
        model.getRiskLevel(
            mlProbability
        );

    vector<string> suspiciousWords =
        model.getSuspiciousWords(
            fullEmail
        );


    // ========================================================
    // SECURITY SCANNER
    // ========================================================

    vector<string> urls =
        scanner.detectURLs(
            fullEmail
        );

    vector<string> keywords =
        scanner.detectKeywords(
            fullEmail
        );

    vector<string> money =
        scanner.detectMoneyPatterns(
            fullEmail
        );

    vector<string> urgency =
        scanner.detectUrgencyWords(
            fullEmail
        );

    vector<string> security =
        scanner.detectSecurityRequests(
            fullEmail
        );

    bool excessiveExclamation =
        scanner.hasExcessiveExclamation(
            fullEmail
        );

    int securityScore =
        scanner.calculateRiskScore(
            fullEmail
        );


    // ========================================================
    // PHISHING
    // ========================================================

    int phishingScore =
        phishing.calculatePhishingScore(
            fullEmail
        );


    // ========================================================
    // RISK CALCULATION
    // ========================================================

    double mlContribution =
        mlProbability * 60.0;

    double securityContribution =
        securityScore * 0.15;

    double phishingContribution =
        phishingScore * 0.15;

    double senderContribution =
        senderRisk * 0.10;


    double finalScore =
        mlContribution
        + securityContribution
        + phishingContribution
        + senderContribution;


    if (finalScore > 100.0)
        finalScore = 100.0;

    if (finalScore < 0.0)
        finalScore = 0.0;


    // ========================================================
    // FINAL CLASSIFICATION
    // ========================================================

    string classification;


    if (
        phishingScore >= 70 ||
        securityScore >= 80
    )
    {
        classification = "SPAM";
    }
    else if (
        mlProbability >= 0.80
    )
    {
        classification = "SPAM";
    }
    else if (
        finalScore >= 70.0
    )
    {
        classification = "SPAM";
    }
    else if (
        finalScore >= 45.0 ||
        mlProbability >= 0.50 ||
        phishingScore >= 40 ||
        securityScore >= 50
    )
    {
        classification = "SUSPICIOUS";
    }
    else
    {
        classification = "HAM";
    }


    // ========================================================
    // DISPLAY RESULT
    // ========================================================

    cout << "\n\n";
    cout << "============================================\n";
    cout << "              NOVA AI RESULT\n";
    cout << "============================================\n";

    cout << "\nSender  : "
         << sanitizeText(email.sender)
         << '\n';

    cout << "Subject : "
         << sanitizeText(email.subject)
         << '\n';


    // ========================================================
    // ML ANALYSIS
    // ========================================================

    cout << "\n------------- ML ANALYSIS -----------------\n";

    cout << fixed << setprecision(2);

    cout << "Prediction       : "
         << mlPrediction
         << '\n';

    cout << "Spam Probability : "
         << mlProbability * 100.0
         << "%\n";

    cout << "Confidence       : "
         << confidence
         << '\n';

    cout << "ML Risk Level    : "
         << mlRisk
         << '\n';

    cout << "Suspicious Words : ";

    printList(suspiciousWords);

    cout << '\n';


    // ========================================================
    // SECURITY
    // ========================================================

    cout << "\n---------- SECURITY ANALYSIS --------------\n";

    cout << "Suspicious URLs  : "
         << urls.size()
         << '\n';

    cout << "Spam Keywords    : ";

    printList(keywords);

    cout << '\n';

    cout << "Money Patterns   : ";

    printList(money);

    cout << '\n';

    cout << "Urgency          : ";

    printList(urgency);

    cout << '\n';

    cout << "Security Requests: ";

    printList(security);

    cout << '\n';

    cout << "Excessive '!'    : "
         << (
             excessiveExclamation
             ? "DETECTED"
             : "No"
         )
         << '\n';

    cout << "Security Score   : "
         << securityScore
         << "/100\n";


    // ========================================================
    // PHISHING
    // ========================================================

    phishing.displayAnalysis(
        fullEmail
    );


    // ========================================================
    // EXPLANATION
    // ========================================================

    explanation.displayExplanation(
        mlProbability,
        securityScore,
        phishingScore,
        senderRisk,
        suspiciousWords,
        keywords,
        urgency,
        security
    );


    // ========================================================
    // RISK BREAKDOWN
    // ========================================================

    cout << "\n------------- RISK BREAKDOWN --------------\n";

    cout << "ML Contribution       : "
         << mlContribution
         << '\n';

    cout << "Security Contribution : "
         << securityContribution
         << '\n';

    cout << "Phishing Contribution : "
         << phishingContribution
         << '\n';

    cout << "Sender Contribution   : "
         << senderContribution
         << '\n';

    cout << "--------------------------------------------\n";

    cout << "FINAL RISK SCORE      : "
         << finalScore
         << "%\n";

    cout << "FINAL CLASSIFICATION  : "
         << classification
         << "\n";


    // ========================================================
    // CONSISTENT NOVA VERDICT
    // ========================================================

    cout << "\n";
    cout << "============================================\n";
    cout << "             NOVA AI VERDICT\n";
    cout << "============================================\n";

    cout << "Risk Score       : "
         << finalScore
         << "%\n";


    string riskLevel;
    string verdict;
    string recommendation;


    if (classification == "SPAM")
    {
        riskLevel = "HIGH";
        verdict = "SPAM";

        recommendation =
            "Do not respond or provide personal information.";
    }
    else if (classification == "SUSPICIOUS")
    {
        riskLevel = "MEDIUM";
        verdict = "SUSPICIOUS";

        recommendation =
            "Exercise caution and verify the sender before responding.";
    }
    else
    {
        riskLevel = "LOW";
        verdict = "SAFE";

        recommendation =
            "No major threat detected.";
    }


    cout << "Risk Level       : "
         << riskLevel
         << '\n';

    cout << "Final Verdict    : "
         << verdict
         << '\n';

    cout << "\nRecommendation:\n"
         << recommendation
         << '\n';

    cout << "============================================\n";


    // ========================================================
    // SAVE HISTORY
    // ========================================================

    history.saveScan(
        fullEmail,
        classification,
        mlProbability * 100.0,
        securityScore,
        finalScore
    );


    // ========================================================
    // SAVE REPORT
    // ========================================================

    ScanReport::saveReport(
        email.sender,
        email.subject,
        classification,
        mlProbability * 100.0,
        securityScore,
        phishingScore,
        senderRisk,
        finalScore,
        suspiciousWords,
        urls,
        keywords,
        urgency,
        security
    );


    cout << "\n";
    cout << "--------------------------------------------\n";
    cout << "Scan saved to history.\n";
    cout << "Detailed report generated.\n";
    cout << "--------------------------------------------\n";
}


// ============================================================
// MAIN
// ============================================================

int main()
{
    NaiveBayes model;
    EmailScanner scanner;
    ScanHistory history;


    cout << "\n";
    cout << "============================================\n";
    cout << "                 NOVA AI\n";
    cout << "        ADVANCED EMAIL PROTECTION\n";
    cout << "============================================\n";


    cout << "\nLoading ML dataset...\n";

    bool loaded =
        model.train(
            "data/sms+spam+collection/SMSSpamCollection"
        );

    if (!loaded)
    {
        cout << "ML model failed to load. Exiting.\n";
        return 1;
    }

    cout << "ML model loaded successfully.\n";


    // ========================================================
    // MENU
    // ========================================================

    while (true)
    {
        cout << "\n";
        cout << "============================================\n";
        cout << "                 NOVA MENU\n";
        cout << "============================================\n";

        cout << "1. Scan Email\n";
        cout << "2. View Scan History\n";
        cout << "3. View Statistics\n";
        cout << "4. View Latest Report\n";
        cout << "5. Clear Scan History\n";
        cout << "6. Exit\n";

        cout << "============================================\n";
        cout << "Enter choice: ";


        string choice;

        if (!getline(
            cin,
            choice
        ))
        {
            break;
        }


        if (choice == "1")
        {
            scanEmail(
                model,
                scanner,
                history
            );
        }
        else if (choice == "2")
        {
            history.displayHistory();
        }
        else if (choice == "3")
        {
            history.displayStatistics();
        }
        else if (choice == "4")
        {
            viewLatestReport();
        }
        else if (choice == "5")
        {
            cout << "\nClear all scan history? (y/n): ";

            string confirm;

            getline(
                cin,
                confirm
            );

            if (
                confirm == "y" ||
                confirm == "Y"
            )
            {
                history.clearHistory();
            }
            else
            {
                cout << "\nOperation cancelled.\n";
            }
        }
        else if (choice == "6")
        {
            cout << "\n";
            cout << "============================================\n";
            cout << "        Thank you for using Nova AI\n";
            cout << "============================================\n";

            break;
        }
        else
        {
            cout << "\nInvalid choice.\n";
            cout << "Please enter a number from 1 to 6.\n";
        }
    }


    return 0;
}