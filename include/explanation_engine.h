#ifndef EXPLANATION_ENGINE_H
#define EXPLANATION_ENGINE_H

#include <string>
#include <vector>

using namespace std;

class ExplanationEngine
{
public:

    vector<string> generateReasons(
        double mlProbability,
        int securityScore,
        int phishingScore,
        int senderRisk,
        const vector<string>& suspiciousWords,
        const vector<string>& keywords,
        const vector<string>& urgency,
        const vector<string>& security
    );

    void displayExplanation(
        double mlProbability,
        int securityScore,
        int phishingScore,
        int senderRisk,
        const vector<string>& suspiciousWords,
        const vector<string>& keywords,
        const vector<string>& urgency,
        const vector<string>& security
    );
};

#endif