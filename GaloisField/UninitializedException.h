#ifndef UNINITIALIZED_EXCEPTION_H
#define UNINITIALIZED_EXCEPTION_H

#include <exception>

struct UninitializedException : public std::exception {
   const char * what () const throw () {
      return "Error: Field has not been initialized.\n";
   }
};

#endif // UNINITIALIZED_EXCEPTION_H
