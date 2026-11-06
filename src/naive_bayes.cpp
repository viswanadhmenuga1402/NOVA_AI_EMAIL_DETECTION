#include "naive_bayes.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <fstream>
#include <iostream>
#include <sstream>
#include <unordered_set>

using namespace std;


// ============================================================
// CONSTRUCTOR
// ============================================================

NaiveBayes::NaiveBayes()
{
    spamMessages = 0;
    hamMessages = 0;

    spamWordCount = 0;
    hamWordCount = 0;

    spamWords.clear();
    hamWords.clear();
}


// ============================================================
// TOKENIZE
// ============================================================

vector<string> NaiveBayes::tokenize(
    const string& text
)
{
    vector<string> words;

    string current;


    for (char ch : text)
    {
        if (
            isalnum(
                static_cast<unsigned char>(ch)
            )
        )
        {
            current += static_cast<char>(
                tolower(
                    static_cast<unsigned char>(ch)
                )
            );
        }
        else
        {
            if (!current.empty())
            {
                words.push_back(current);
                current.clear();
            }
        }
    }


    if (!current.empty())
    {
        words.push_back(current);
    }


    return words;
}


// ============================================================
// TRAIN
// ============================================================

bool NaiveBayes::train(
    const string& filename
)
{
    ifstream file(filename);


    if (!file.is_open())
    {
        cerr << "\nERROR: Could not open dataset:\n";
        cerr << filename << "\n";
        return false;
    }


    // Reset model
    spamMessages = 0;
    hamMessages = 0;

    spamWordCount = 0;
    hamWordCount = 0;

    spamWords.clear();
    hamWords.clear();


    string line;


    while (getline(file, line))
    {
        if (line.empty())
        {
            continue;
        }


        string label;
        string message;


        // Dataset format:
        // ham<TAB>message
        // spam<TAB>message

        size_t tab =
            line.find('\t');


        if (tab != string::npos)
        {
            label =
                line.substr(
                    0,
                    tab
                );

            message =
                line.substr(
                    tab + 1
                );
        }
        else
        {
            stringstream ss(line);

            ss >> label;

            getline(
                ss,
                message
            );
        }


        vector<string> words =
            tokenize(message);


        if (label == "spam")
        {
            spamMessages++;


            for (
                const string& word : words
            )
            {
                spamWords[word]++;

                spamWordCount++;
            }
        }
        else if (label == "ham")
        {
            hamMessages++;


            for (
                const string& word : words
            )
            {
                hamWords[word]++;

                hamWordCount++;
            }
        }
    }


    file.close();


    cout << "Training completed.\n";

    cout << "Spam messages : "
         << spamMessages
         << "\n";

    cout << "Ham messages  : "
         << hamMessages
         << "\n";

    if (spamMessages + hamMessages == 0)
    {
        return false;
    }

    return true;
}


// ============================================================
// SPAM PROBABILITY
// ============================================================

double NaiveBayes::spamProbability(
    const vector<string>& words
)
{
    if (
        spamMessages == 0 ||
        hamMessages == 0
    )
    {
        return 0.5;
    }


    // --------------------------------------------------------
    // Vocabulary
    // --------------------------------------------------------

    // Count the unique vocabulary across both classes so shared
    // words are not double-counted in the Laplace smoothing
    // denominator.
    unordered_set<string> vocabulary;

    for (const auto& entry : spamWords)
    {
        vocabulary.insert(entry.first);
    }

    for (const auto& entry : hamWords)
    {
        vocabulary.insert(entry.first);
    }

    size_t vocabularySize =
        vocabulary.size();


    if (vocabularySize == 0)
    {
        return 0.5;
    }


    // --------------------------------------------------------
    // Priors
    // --------------------------------------------------------

    double totalMessages =
        static_cast<double>(
            spamMessages + hamMessages
        );


    double spamPrior =
        spamMessages /
        totalMessages;


    double hamPrior =
        hamMessages /
        totalMessages;


    // --------------------------------------------------------
    // Log probabilities
    // --------------------------------------------------------

    double logSpam =
        log(spamPrior);


    double logHam =
        log(hamPrior);


    // Laplace smoothing
    const double alpha = 1.0;


    double spamDenominator =
        spamWordCount
        +
        alpha * static_cast<double>(vocabularySize);


    double hamDenominator =
        hamWordCount
        +
        alpha * static_cast<double>(vocabularySize);


    // --------------------------------------------------------
    // Process words
    // --------------------------------------------------------

    for (
        const string& word : words
    )
    {
        int spamCount = 0;

        int hamCount = 0;


        auto spamIt =
            spamWords.find(word);


        if (
            spamIt != spamWords.end()
        )
        {
            spamCount =
                spamIt->second;
        }


        auto hamIt =
            hamWords.find(word);


        if (
            hamIt != hamWords.end()
        )
        {
            hamCount =
                hamIt->second;
        }


        double spamLikelihood =
            (spamCount + alpha)
            /
            spamDenominator;


        double hamLikelihood =
            (hamCount + alpha)
            /
            hamDenominator;


        logSpam +=
            log(spamLikelihood);


        logHam +=
            log(hamLikelihood);
    }


    // --------------------------------------------------------
    // Convert log probability
    // --------------------------------------------------------

    double maximum =
        max(
            logSpam,
            logHam
        );


    double spamExp =
        exp(
            logSpam - maximum
        );


    double hamExp =
        exp(
            logHam - maximum
        );


    double probability =
        spamExp /
        (
            spamExp + hamExp
        );

    if (!isfinite(probability))
    {
        probability = 0.5;
    }


    // --------------------------------------------------------
    // Safety
    // --------------------------------------------------------

    if (probability < 0.0)
    {
        probability = 0.0;
    }


    if (probability > 1.0)
    {
        probability = 1.0;
    }


    return probability;
}


// ============================================================
// GET SPAM PROBABILITY
// ============================================================

double NaiveBayes::getSpamProbability(
    const string& text
)
{
    vector<string> words =
        tokenize(text);


    return spamProbability(
        words
    );
}


// ============================================================
// PREDICT
// ============================================================

string NaiveBayes::predict(
    const string& text
)
{
    double probability =
        getSpamProbability(
            text
        );


    if (probability >= 0.50)
    {
        return "SPAM";
    }


    return "HAM";
}


// ============================================================
// CONFIDENCE
// ============================================================

string NaiveBayes::getConfidence(
    double probability
)
{
    double percentage =
        probability * 100.0;


    double confidence =
        max(
            percentage,
            100.0 - percentage
        );


    if (confidence >= 90.0)
    {
        return "Very High";
    }


    if (confidence >= 75.0)
    {
        return "High";
    }


    if (confidence >= 60.0)
    {
        return "Medium";
    }


    return "Low";
}


// ============================================================
// RISK LEVEL
// ============================================================

string NaiveBayes::getRiskLevel(
    double probability
)
{
    if (probability >= 0.80)
    {
        return "HIGH";
    }


    if (probability >= 0.50)
    {
        return "MEDIUM";
    }


    if (probability >= 0.20)
    {
        return "LOW";
    }


    return "VERY LOW";
}


// ============================================================
// SUSPICIOUS WORDS
// ============================================================

vector<string> NaiveBayes::getSuspiciousWords(
    const string& text
)
{
    vector<string> words =
        tokenize(text);


    vector<string> suspicious;

    unordered_set<string> seenSuspicious;


    const vector<string> spamIndicators =
    {
        "free",
        "winner",
        "win",
        "prize",
        "cash",
        "money",
        "urgent",
        "offer",
        "bonus",
        "claim",
        "click",
        "verify",
        "password",
        "account",
        "bank",
        "credit",
        "loan",
        "congratulations",
        "selected",
        "reward",
        "limited",
        "subscribe",
        "unsubscribe"
    };


    for (
        const string& word : words
    )
    {
         if (
             find(
                 spamIndicators.begin(),
                 spamIndicators.end(),
                 word
             )
             != spamIndicators.end()
         )
         {
             if (seenSuspicious.insert(word).second)
             {
                 suspicious.push_back(word);
             }
         }

    }


    return suspicious;
}


// ============================================================
// IS TRAINED
// ============================================================

bool NaiveBayes::isTrained() const
{
    return (spamMessages + hamMessages) > 0;
}
