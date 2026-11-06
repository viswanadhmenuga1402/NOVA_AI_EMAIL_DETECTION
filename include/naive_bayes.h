#ifndef NAIVE_BAYES_H
#define NAIVE_BAYES_H

#include <string>
#include <vector>
#include <unordered_map>

using namespace std;

class NaiveBayes
{
private:

    int spamMessages;
    int hamMessages;

    int spamWordCount;
    int hamWordCount;

    unordered_map<string, int> spamWords;
    unordered_map<string, int> hamWords;

    vector<string> tokenize(
        const string& text
    );


public:

    NaiveBayes();


    // Train using SMS Spam Collection
    // Returns true on success, false if the dataset could not be opened.
    bool train(
        const string& filename
    );


    // Calculate probability from tokenized words
    double spamProbability(
        const vector<string>& words
    );


    // Calculate probability from raw text
    double getSpamProbability(
        const string& text
    );


    // Predict SPAM or HAM
    string predict(
        const string& text
    );

    // Whether the model has been trained
    bool isTrained() const;


    // Confidence level
    string getConfidence(
        double probability
    );


    // Risk level
    string getRiskLevel(
        double probability
    );


    // Words that indicate spam
    vector<string> getSuspiciousWords(
        const string& text
    );
};

#endif