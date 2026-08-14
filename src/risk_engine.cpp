#include "risk_engine.h"

#include <iomanip>
#include <iostream>

using namespace std;


// ============================================================
// GET VERDICT
// ============================================================

string RiskEngine::getVerdict(
    double score
)
{
    if (score >= 85.0)
    {
        return "CRITICAL SPAM";
    }
    else if (score >= 70.0)
    {
        return "HIGH RISK SPAM";
    }
    else if (score >= 50.0)
    {
        return "SUSPICIOUS";
    }
    else if (score >= 30.0)
    {
        return "LOW RISK";
    }

    return "SAFE";
}


// ============================================================
// GET RISK LEVEL
// ============================================================

string RiskEngine::getRiskLevel(
    double score
)
{
    if (score >= 85.0)
    {
        return "CRITICAL";
    }
    else if (score >= 70.0)
    {
        return "HIGH";
    }
    else if (score >= 50.0)
    {
        return "MEDIUM";
    }
    else if (score >= 30.0)
    {
        return "LOW";
    }

    return "MINIMAL";
}


// ============================================================
// RECOMMENDATION
// ============================================================

string RiskEngine::getRecommendation(
    const string& verdict
)
{
    if (verdict == "CRITICAL SPAM")
    {
        return "Do not open links or attachments. Delete the email.";
    }

    if (verdict == "HIGH RISK SPAM")
    {
        return "Do not interact with this email. Verify the sender independently.";
    }

    if (verdict == "SUSPICIOUS")
    {
        return "Exercise caution and verify the sender before responding.";
    }

    if (verdict == "LOW RISK")
    {
        return "Email appears mostly safe, but remain cautious.";
    }

    return "No major threat detected.";
}


// ============================================================
// DISPLAY VERDICT
// ============================================================

void RiskEngine::displayVerdict(
    double score
)
{
    string verdict =
        getVerdict(score);

    string level =
        getRiskLevel(score);

    string recommendation =
        getRecommendation(verdict);


    cout << "\n";
    cout << "============================================\n";
    cout << "             NOVA AI VERDICT\n";
    cout << "============================================\n";


    cout << fixed
         << setprecision(2);


    cout << "Risk Score       : "
         << score
         << "%\n";


    cout << "Risk Level       : "
         << level
         << "\n";


    cout << "Final Verdict    : "
         << verdict
         << "\n";


    cout << "\nRecommendation:\n";
    cout << recommendation
         << "\n";


    cout << "============================================\n";
}