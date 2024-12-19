#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <ctime>

#include "Crypto.h"

std::string generatePassword(
    int length,
    bool includeLowercase,
    bool includeUppercase,
    bool includeDigits,
    bool includeSpecialChars,
    bool excludeAmbiguous,
    bool includeSpaces,
    bool includeBrackets,
    bool includeMinus,
    bool includeUnderline,
    bool memorable
) {
    if (length <= 0) {
        throw std::invalid_argument("Password length must be greater than zero.");
    }

    if (!(includeLowercase || includeUppercase || includeDigits || includeSpecialChars || includeBrackets)) {
        return "";
    }

    CryptoManager crypto;

    const std::string lowercase = "abcdefghijklmnopqrstuvwxyz";
    const std::string uppercase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const std::string digits = "0123456789";
    const std::string specialChars = "!@#$%^*=+|;:,.?/";
    const std::string ambiguousChars = "l1O0oi|I";

    const std::string vowels = "aeiou";
    const std::string consonants = "bcdfghjklmnpqrstvwxyz";

    if (memorable) {
        if (!(includeLowercase || includeUppercase || includeDigits || includeSpaces)) {
            throw std::runtime_error("Memorable passwords require at least one of lowercase, uppercase, digits, or spaces.");
        }

        std::string password;
        char lastChar = '\0';

        std::string pool;

        if (includeUppercase && includeLowercase) {
            pool = lowercase + uppercase;
        }
        else if (includeUppercase) {
            pool = uppercase;
        }
        else if (includeLowercase) {
            pool = lowercase;
        }

        if (includeDigits) {
            pool += digits;
        }

        if (includeSpaces) {
            pool += " ";
        }

        if (excludeAmbiguous) {
            for (char c : ambiguousChars) {
                pool.erase(std::remove(pool.begin(), pool.end(), c), pool.end());
            }
        }

        if (pool.empty()) {
            throw std::runtime_error("Character pool is empty. Cannot generate password.");
        }

        for (int i = 0; i < length; ++i) {
            char nextChar;
            do {
                nextChar = pool[crypto.getRandomNumber(0, pool.size() - 1)];
            } while (nextChar == lastChar);

            password += nextChar;
            lastChar = nextChar;
        }

        return password;
    }

    std::string characterPool;

    if (includeLowercase) {
        characterPool += lowercase;
    }

    if (includeUppercase) {
        characterPool += uppercase;
    }

    if (includeDigits) {
        characterPool += digits;
    }

    if (includeSpecialChars) {
        characterPool += specialChars;
    }

    if (includeSpaces) {
        characterPool += " ";
    }

    if (includeMinus) {
        characterPool += "-";
    }

    if (includeUnderline) {
        characterPool += "_";
    }

    if (includeBrackets) {
        characterPool += "[]{}<>()";
    }

    if (excludeAmbiguous) {
        for (char c : ambiguousChars) {
            characterPool.erase(std::remove(characterPool.begin(), characterPool.end(), c), characterPool.end());
        }
    }

    if (characterPool.empty()) {
        throw std::runtime_error("Character pool is empty. Cannot generate password.");
    }

    std::string password;
    char lastChar = '\0';

    for (int i = 0; i < length; ++i) {
        char nextChar;
        do {
            nextChar = characterPool[crypto.getRandomNumber(0, characterPool.size() - 1)];
        } while (nextChar == lastChar);

        password += nextChar;
        lastChar = nextChar;
    }

    return password;
}