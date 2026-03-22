#ifndef COMPOSITE_EXCEPTION_H
#define COMPOSITE_EXCEPTION_H

#include <exception>

struct CompositeException : public std::exception {
   const char * what () const throw () {
      return "Error: Given number is not prime.\n";
   }
};

#endif // COMPOSITE_EXCEPTION_H
