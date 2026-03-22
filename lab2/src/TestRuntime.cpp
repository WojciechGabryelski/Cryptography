#include <iostream>
#include <gmpxx.h>
#include "GFE.h"
#include "GF2E.h"
#include <chrono>

typedef mpz_class T;

void test_GF_runtime() {
    T a = (T) 0x0000000fffffffL;
    T b = (T) 0x00000000000002L;
    GF<T>::init((T) "19327281737655084535892011671992951921655977783765086077199047221167012535290346003234422487231888890011834896245923934571113922139653643209852371896888031137542825432342456677552143106518127817898020676861955936752938754539166850631821934043918381125243790092845320737471552268876045735207586803150380363924346258603193870363213573791465697262795617427661755215340629777719064638702722195424914682905778415560578008320535905669758154682069812015267283526539751664986521494556772657229591992390491718935625622362396123967636343132179368577940011827511078776580959470015033801526154158712810444697147613184391076904960");
    GF<T> g((T) "207460104821768042173408762317638726147832104796218756738201497234870321678532010127365732810837587213");
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        g.pow(a);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        g.pow(b);
    }
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
}

void test_GF2E_runtime() {
    T a = (T) 0x0000000fffffffL;
    T b = (T) 0x00000000000002L;
    GF2E<T>::init((T) 8732637);
    GF2E<T> g((T) 983135);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        g.pow(a);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 1000; ++i) {
        g.pow(b);
    }
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
}

void test_GFE_runtime() {
    T a = (T) 0x0000000fffffffL;
    T b = (T) 0x00000000000002L;
    GF<T>::init((T) 7);
    Polynomial<GF<T>> w({(T) 4, (T) 4, (T) 1, (T) 2, (T) 5, (T) 6, (T) 5, (T) 5, (T) 1, (T) 5, (T) 1});
    GFE<T>::init(w);
    Polynomial<GF<T>> u({(T) 1, (T) 2, (T) 3, (T) 4, (T) 5, (T) 6, (T) 1, (T) 2, (T) 3, (T) 4});
    GFE<T> g(u);
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        g.pow(a);
    }
    auto stop = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 100; ++i) {
        g.pow(b);
    }
    stop = std::chrono::high_resolution_clock::now();
    duration = std::chrono::duration_cast<std::chrono::microseconds>(stop - start);
    std::cout << duration.count() << "\n";
}

int main() {
    test_GF_runtime();
    test_GF2E_runtime();
    test_GFE_runtime();
    return 0;
}