#ifndef REDUCIBLE_EXCEPTION_H
#define REDUCIBLE_EXCEPTION_H

#include <exception>

struct ReducibleException : public std::exception {
   const char * what () const throw () {
      return "Error: Given polynomial is not irreducible.\n";
   }
};

#endif // REDUCIBLE_EXCEPTION_H
