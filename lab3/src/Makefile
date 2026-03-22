all:
	g++ Test.cpp -o Test -O3 -Wall -pedantic -lgmpxx -lgmp -I../../GaloisField -IEllipticCurve
	g++ DiffieHellmanEC.cpp -fPIC $(shell python3 -m pybind11 --includes) -shared -o diffie_hellman_ec$(shell python3-config --extension-suffix) -O3 -Wall -pedantic -lgmpxx -lgmp -I../../GaloisField -IEllipticCurve
	g++ SchnorrSignature.cpp -fPIC $(shell python3 -m pybind11 --includes) -shared -o schnorr_signature$(shell python3-config --extension-suffix) -O3 -Wall -pedantic -lgmpxx -lgmp -lcrypto -lssl -I../../GaloisField -IEllipticCurve
	g++ Protocol.cpp -fPIC $(shell python3 -m pybind11 --includes) -shared -o protocol$(shell python3-config --extension-suffix) -O3 -Wall -pedantic -lgmpxx -lgmp -lcrypto -lssl -I../../GaloisField -IEllipticCurve
