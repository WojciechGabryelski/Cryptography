#ifndef UNINITIALIZED_EC_EXCEPTION_H
#define UNINITIALIZED_EC_EXCEPTION_H

#include <exception>

struct UninitializedECException : public std::exception {
   const char * what () const throw () {
      return "Error: Eliptic curve has not been initialized.\n";
   }
};

#endif // UNINITIALIZED_EC_EXCEPTION_H
