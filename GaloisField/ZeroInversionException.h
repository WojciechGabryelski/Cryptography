#ifndef ZERO_INVERSION_EXCEPTION_H
#define ZERO_INVERSION_EXCEPTION_H

#include <exception>

struct ZeroInversionException : public std::exception {
   const char * what () const throw () {
      return "Error: Attempt to divide by zero.\n";
   }
};

#endif // ZERO_INVERSION_EXCEPTION_H
