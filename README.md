# lwip_refactor

This project is an attempt to re-write the Light Weight IP stack in modern C++.

## Principles

* All functions that do not return a value should return a bool indicating success or failure. If an error occurs, the function should set an error value.

## TODO items

* Use rocksdb for key/value 'global' storage
* Separate protocols into static libraries
* Create C API interfaces for calling with external programs that are not C++
* Re-implement all code using C++ 17 spec.
* Document using google style
* Implement VXLAN protocol
* Replace LinkedLists with arrays or vectors

## References

* RocksDB: [https://rocksdb.org/docs/getting-started.html]
