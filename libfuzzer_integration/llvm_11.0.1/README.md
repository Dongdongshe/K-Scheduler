### Building llvm-11.0.1 with K-Scheduler
1. Install Ninja:
    ```sh
    sudo apt-get install ninja-build
    ```

2. Configure and build LLVM and Clang:

    ```sh
    mkdir build
    cd build
    # configure cmake
    cmake -G Ninja -DLLVM_ENABLE_PROJECTS="clang;compiler-rt" -DCMAKE_BUILD_TYPE=release -DLLVM_TARGETS_TO_BUILD=host ../llvm 
    # build llvm
    ninja 
     ```    
