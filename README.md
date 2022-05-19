
# K-Scheduler: Effective Seed Scheduling for Fuzzing with Graph Centrality Analysis (IEEE S&P'22)
A generic seed scheduler for fuzzers (LibFuzzer and AFL) and concolic execution engine (QSYM). Check the following [1 minute video](https://www.youtube.com/watch?v=VVZZpQiIsm4) to get a sense about how K-Scheduler works. Read our [paper](https://arxiv.org/abs/2203.12064) for more details.

<a href="http://www.youtube.com/watch?feature=player_embedded&v=VVZZpQiIsm4
" target="_blank"><img src="http://img.youtube.com/vi/VVZZpQiIsm4/0.jpg" 
alt="IMAGE ALT TEXT HERE" width="240" height="180" border="10" /></a>

### Prerequisite
- Python 3.7
- LLVM 11.0.1
- [wllvm](https://github.com/travitch/whole-program-llvm)
- [NetworKit](https://networkit.github.io/)

### Usage 
We use harfbuzz as an example
1. Open a terminal to run LibFuzzer:
    ```sh
    ./harfbuzz-1.3.2-fsanitize_fuzzer_kscheduler -kscheduler=1 -min_num_mutations_for_each_seed=200 ./tmp_seeds/ seeds/
    ```
2. Open another terminal to run graph analysis module:
    ```sh
    python3 ./gen_dyn_weight.py
    ```
### Tested programs
We provide 12 programs from Google FuzzBench to reproduce our results, [K-Scheduler/libfuzzer_integration/test_programs](https://github.com/Dongdongshe/K-Scheduler/tree/main/libfuzzer_integration/test_programs), [K-Scheduler/afl_integration/test_programs](https://github.com/Dongdongshe/K-Scheduler/tree/main/afl_integration/test_programs) and [K-Scheduler/qsym_integration/test_programs](https://github.com/Dongdongshe/K-Scheduler/tree/main/qsym_integration/test_programs)

### Run K-Scheduler on a new program
Check tutorials at [K-Scheduler/libfuzzer_integration/build_example](https://github.com/Dongdongshe/K-Scheduler/tree/main/afl_integration/build_example), [K-Scheduler/afl_integration/build_example](https://github.com/Dongdongshe/K-Scheduler/tree/main/afl_integration/build_example) and [K-Scheduler/qsym_integration/build_example](https://github.com/Dongdongshe/K-Scheduler/tree/main/qsym_integration/build_example) 

### Contact
Feel free to send me email about K-Scheduler. dongdong at cs.columbia.edu
