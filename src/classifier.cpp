#include "classifier.h"
#include <iostream>
#include <fstream>
#include <vector>
#include <algorithm>
#include <sstream>
#include <cctype>

using namespace std;

bool isSpam(string email)
{
    vector<string> spamWords;
    string word;

    // Open spam words file
    ifstream file("data/spam_words.txt");

    if (!file)
    {
        cout << "Error opening spam_words.txt file!" << endl;
        return false;
    }

    // Load spam words
    while (file >> word)
    {
        spamWords.push_back(word);
    }

    file.close();

    // Convert email to lowercase
    transform(email.begin(), email.end(), email.begin(),
              [](unsigned char c)
              {
                  return tolower(c);
              });

    int spamScore = 0;
    vector<string> detectedWords;

    string currentWord;
    stringstream ss(email);

    // =================================
    // PHASE 1: SMART RISK SCORING
    // =================================

    while (ss >> currentWord)
    {
        // Remove punctuation
        currentWord.erase(
            remove_if(currentWord.begin(),
                      currentWord.end(),
                      [](unsigned char c)
                      {
                          return ispunct(c);
                      }),
            currentWord.end());

        for (string spamWord : spamWords)
        {
            transform(spamWord.begin(), spamWord.end(),
                      spamWord.begin(),
                      [](unsigned char c)
                      {
                          return tolower(c);
                      });

            if (currentWord == spamWord)
            {
                spamScore += 10;
                detectedWords.push_back(currentWord);
            }
        }
    }

    // =================================
    // PHASE 4: PHISHING & URL DETECTION
    // =================================

    bool suspiciousURL = false;
    bool phishingPhrase = false;

    // Detect HTTP/HTTPS links
    if (email.find("http://") != string::npos ||
        email.find("https://") != string::npos)
    {
        spamScore += 20;
        suspiciousURL = true;
    }

    // Detect common phishing phrases
    if (email.find("click here") != string::npos ||
        email.find("verify your account") != string::npos ||
        email.find("confirm your password") != string::npos ||
        email.find("account blocked") != string::npos ||
        email.find("login immediately") != string::npos)
    {
        spamScore += 20;
        phishingPhrase = true;
    }

    // Maximum score
    if (spamScore > 100)
        spamScore = 100;

    // =================================
    // PHASE 3: CONFIDENCE
    // =================================

    int confidence;

    if (spamScore >= 20)
        confidence = spamScore;
    else
        confidence = 100 - spamScore;

    // =================================
    // RESULT
    // =================================

    cout << "\n==============================" << endl;
    cout << "       EMAIL ANALYSIS" << endl;
    cout << "==============================" << endl;

    cout << "Risk Score : " << spamScore << "%" << endl;
    cout << "Confidence : " << confidence << "%" << endl;

    // Risk level
    if (spamScore >= 70)
        cout << "Risk Level : HIGH" << endl;
    else if (spamScore >= 40)
        cout << "Risk Level : MEDIUM" << endl;
    else
        cout << "Risk Level : LOW" << endl;

    // =================================
    // EXPLAINABLE DETECTION
    // =================================

    cout << "\nDetected Suspicious Words:" << endl;

    if (detectedWords.empty())
    {
        cout << " - None" << endl;
    }
    else
    {
        for (string w : detectedWords)
        {
            cout << " - " << w << endl;
        }
    }

    // Phishing warnings
    cout << "\nSecurity Analysis:" << endl;

    if (suspiciousURL)
        cout << " ! Suspicious URL detected" << endl;

    if (phishingPhrase)
        cout << " ! Phishing phrase detected" << endl;

    if (!suspiciousURL && !phishingPhrase)
        cout << " - No phishing indicators detected" << endl;

    // =================================
    // FINAL CLASSIFICATION
    // =================================

    cout << "\nClassification: ";

    if (spamScore >= 20)
        cout << "SPAM EMAIL" << endl;
    else
        cout << "NOT SPAM EMAIL" << endl;

    cout << "==============================" << endl;

    return spamScore >= 20;
}