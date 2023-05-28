#include <stdint.h>
#include <stdio.h>

#include <fuzzer/FuzzedDataProvider.h>
#include "pqxx/pqxx"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    FuzzedDataProvider provider(data, size);
    std::string str = provider.ConsumeRandomLengthString();
    pqxx::params p;
    p.append(str);

    return 0;
}
