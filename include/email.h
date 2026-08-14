 #ifndef EMAIL_H
#define EMAIL_H

#include <string>

using namespace std;

struct Email
{
    string sender;
    string subject;
    string body;

    // Return complete email text
    string getFullText() const;
};

#endif
