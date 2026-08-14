#include "explanation_engine.h"

#include <iomanip>
#include <iostream>

using namespace std;


// ============================================================
// Generate explanation reasons
// ============================================================

vector<string>
ExplanationEngine::generateReasons(
    double mlProbability,
    int securityScore,
    int phishingScore,
    int senderRisk,
    const vector<string>& suspiciousWords,
    const vector<string>& keywords,
    const vector<string>& urgency,
    const vector<string>& security
)
{
    vector<string> reasons;


    // --------------------------------------------------------
    // Machine Learning
    // --------------------------------------------------------

    if (mlProbability >= 0.80)
    {
        reasons.push_back(
            "Machine learning detected a high probability of spam."
        );
    }
    else if (mlProbability >= 0.60)
    {
        reasons.push_back(
            "Machine learning detected suspicious spam-like patterns."
        );
    }


    // --------------------------------------------------------
    // Suspicious words
    // --------------------------------------------------------

    if (!suspiciousWords.empty())
    {
        reasons.push_back(
            "Suspicious words were detected in the message."
        );
    }


    // --------------------------------------------------------
    // Security keywords
    // --------------------------------------------------------

    if (!keywords.empty())
    {
        reasons.push_back(
            "Known spam-related keywords were detected."
        );
    }


    // --------------------------------------------------------
    // Urgency
    // --------------------------------------------------------

    if (!urgency.empty())
    {
        reasons.push_back(
            "Urgency or pressure-based language was detected."
        );
    }


    // --------------------------------------------------------
    // Security requests
    // --------------------------------------------------------

    if (!security.empty())
    {
        reasons.push_back(
            "The message requests sensitive account or security information."
        );
    }


    // --------------------------------------------------------
    // Security score
    // --------------------------------------------------------

    if (securityScore >= 70)
    {
        reasons.push_back(
            "The security-rule score is very high."
        );
    }
    else if (securityScore >= 40)
    {
        reasons.push_back(
            "Multiple security-risk indicators were detected."
        );
    }


    // --------------------------------------------------------
    // Phishing
    // --------------------------------------------------------

    if (phishingScore >= 70)
    {
        reasons.push_back(
            "The URL analysis indicates a high phishing risk."
        );
    }
    else if (phishingScore >= 40)
    {
        reasons.push_back(
            "The message contains potentially suspicious URLs."
        );
    }


    // --------------------------------------------------------
    // Sender
    // --------------------------------------------------------

    if (senderRisk >= 70)
    {
        reasons.push_back(
            "The sender has a high-risk profile."
        );
    }
    else if (senderRisk >= 40)
    {
        reasons.push_back(
            "The sender has suspicious characteristics."
        );
    }


    // --------------------------------------------------------
    // Nothing suspicious
    // --------------------------------------------------------

    if (reasons.empty())
    {
        reasons.push_back(
            "No major suspicious indicators were detected."
        );
    }


    return reasons;
}


// ============================================================
// Display explanation
// ============================================================

void
ExplanationEngine::displayExplanation(
    double mlProbability,
    int securityScore,
    int phishingScore,
    int senderRisk,
    const vector<string>& suspiciousWords,
    const vector<string>& keywords,
    const vector<string>& urgency,
    const vector<string>& security
)
{
    vector<string> reasons =
        generateReasons(
            mlProbability,
            securityScore,
            phishingScore,
            senderRisk,
            suspiciousWords,
            keywords,
            urgency,
            security
        );


    cout << "\n";
    cout << "---------- WHY NOVA FLAGGED THIS ---------\n";


    for (size_t i = 0; i < reasons.size(); i++)
    {
        cout << i + 1
             << ". "
             << reasons[i]
             << "\n";
    }


    cout << "\n";
    cout << "Risk Components:\n";


    cout << fixed
         << setprecision(2);


    cout << "  ML Risk        : "
         << mlProbability * 100.0
         << "%\n";


    cout << "  Security Risk  : "
         << securityScore
         << "/100\n";


    cout << "  Phishing Risk  : "
         << phishingScore
         << "/100\n";


    cout << "  Sender Risk    : "
         << senderRisk
         << "/100\n";


    cout << "--------------------------------------------\n";
}
