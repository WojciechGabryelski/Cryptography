all:
	g++ Test.cpp -o Test -O3 -Wall -pedantic -lgmpxx -lgmp -I../../GaloisField
	g++ TestRuntime.cpp -o TestRuntime -O3 -Wall -pedantic -lgmpxx -lgmp -I../../GaloisField
	g++ DiffieHellman.cpp -fPIC $(shell python3 -m pybind11 --includes) -shared -o diffie_hellman$(shell python3-config --extension-suffix) -O3 -Wall -pedantic -lgmpxx -lgmp -I../../GaloisField
