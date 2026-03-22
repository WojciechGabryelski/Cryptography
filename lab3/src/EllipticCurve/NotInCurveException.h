#ifndef NOT_IN_CURVE_EXCEPTION_H
#define NOT_IN_CURVE_EXCEPTION_H

#include <exception>

struct NotInCurveException : public std::exception {
   const char * what () const throw () {
      return "Error: The point does not belong to the curve.\n";
   }
};

#endif // NOT_IN_CURVE_EXCEPTION_H