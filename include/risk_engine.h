#ifndef RISK_ENGINE_H
#define RISK_ENGINE_H

#include <string>

using namespace std;

class RiskEngine
{
public:

    string getVerdict(double score);

    string getRiskLevel(double score);

    string getRecommendation(
        const string& verdict
    );

    void displayVerdict(
        double score
    );
};

#endif