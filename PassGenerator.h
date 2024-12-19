#ifndef PASS_GENERATOR_H
#define PASS_GENERATOR_H

std::string generatePassword(int length, bool includeLowercase, bool includeUppercase, bool includeDigits,
    bool includeSpecialChars, bool excludeAmbiguous, bool includeSpaces,
    bool includeBrackets, bool includeMinus, bool includeUnderline, bool memorable);

#endif