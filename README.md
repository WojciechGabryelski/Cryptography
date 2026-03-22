# Cryptography

This collection contains solutions to tasks from cryptography laboratory assignments, including:

 - finding collisions in the MD5 hash function,
 - various implementations of Galois fields (separate implementations for $\mathbb{F}_p$ and $\mathbb{F}_{p^k}$ for any prime number $p$ and any positive integer $k$, as well as an optimized implementation for binary field $\mathbb{F}_{2^k}$), along with the Diffie-Hellman protocol implemented for all these fields,
 - implementations of elliptic curve groups over $\mathbb{F}_{p^k}$ and $\mathbb{F}_{2^k}$ for any prime number $p$ and positive integer $k$, including the Diffie-Hellman protocol and Schnorr signature.

Detailed task descriptions are available in the .pdf files located in the subdirectories of this project. The assignments were prepared by M.Sc. Eng. Marcin Słowik. All solutions were implemented in C++. To accelerate MD5 collision search, parallel computations on a GPU were utilized using CUDA. Correctness tests for the Galois field implementations, Diffie-Hellman protocols, and Schnorr signatures were written in Python, using an API developed by M.Sc. Eng. Marcin Słowik.

# Kryptografia

Zbiór rozwiązań zadań z list laboratoryjnych z kryptografii obejmuje:

 - znajdowanie kolizji funkcji haszującej MD5,
 - różne implementacje ciał Galois (osobne dla $\mathbb{F}p$ oraz $\mathbb{F}_{p^k}$ dla dowolnej liczby pierwszej $p$ i dodatniej liczby naturalnej $k$, a także zoptymalizowana implementacja dla ciał $\mathbb{F}_{2^k}$), wraz z implementacją protokołu Diffiego-Hellmana dla wszystkich tych ciał,
 - implementacje grup krzywych eliptycznych nad ciałami $\mathbb{F}_{p^k}$ i $\mathbb{F}_{2^k}$ dla dowolnej liczby pierwszej $p$ i dodatniej liczby naturalnej $k$, wraz z implementacją protokołu Diffiego-Hellmana oraz podpisu Schnorra.

Szczegółowe opisy zadań znajdują się w plikach .pdf w podkatalogach tego projektu. Listy zadań opracował mgr inż. Marcin Słowik. Wszystkie rozwiązania zostały napisane w języku C++. Aby przyspieszyć znajdowanie kolizji MD5, wykorzystano obliczenia równoległe na karcie graficznej przy użyciu CUDA. Testy poprawności implementacji ciał Galois, protokołów Diffiego-Hellmana oraz podpisów Schnorra napisano w Pythonie, korzystając z API opracowanego przez mgr. inż. Marcina Słowika.
