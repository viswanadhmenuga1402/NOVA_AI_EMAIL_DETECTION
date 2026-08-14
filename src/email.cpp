#include "email.h"

string Email::getFullText() const
{
    return sender + " " +
           subject + " " +
           body;
}