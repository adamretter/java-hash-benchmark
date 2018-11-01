# Java Hash Performance Benchmark

Some really basic code for benchmarking the performance of hash functions in Java.

Two different types of benchmark:
1) hashing an in-memory buffer
2) incrementally hashing a file, by updating a digest with a fixed size buffer.


## Results

Test system: Apple MacBook Pro (Retina, 15-inch, Mid 2015) / 2.8 GHz Intel Core i7 / 16 GB 1600 MHz DDR3 / 1 TB Apple SSD

![Chart of in-memory buffer hash benchmark results](https://github.com/adamretter/java-hash-benchmark/raw/master/doc/fixed-hash-benchmarks.png "In-memory Buffer Hash Benchmark Results")

![Chart of file stream hash benchmark results](https://github.com/adamretter/java-hash-benchmark/raw/master/doc/file-hash-benchmarks.png "File Stream Hash Benchmark Results")



## TODO

1. Switch to a more rigorous benchmark methodology using Jmh, yada, yada, ...

