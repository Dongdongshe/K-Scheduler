#### Run libfuzzer_libxml_kscheduler
1. Open a terminal to run fuzzer:
    ```sh
    cd [path to K-Schduler repo]/K-Scheduler/libfuzzer_integration/test_programs/libxml/kscheduler 
    # clean fuzzer corpus and other meta data generated by fuzzer
    rm -rf tmp_seeds/ cov_stats cur_coverage dyn_katz_cent 
    mkdir tmp_seeds
    # reset signal file for graph computation module
    echo 0 > signal
    # run libfuzzer_kscheduler
    ./libxml2-v2.9.2-fsanitize_fuzzer_kscheduler -dict=xml.dict -kscheduler=1 -min_num_mutations_for_each_seed=200 ./tmp_seeds/ seeds/
    ```
2. Open another terminal to run graph computation module:
    ```sh
    python3 ./gen_dyn_weight.py
    ```

#### Run libfuzzer_libxml_entropic
1. Open a terminal to run fuzzer:
    ```sh
    cd [path to K-Schduler repo]/K-Scheduler/libfuzzer_integration/test_programs/libxml/entropic 
    # clean fuzzer corpus and other meta data generated by fuzzer
    rm -rf tmp_seeds/ cov_stats  
    mkdir tmp_seeds
    # run libfuzzer_entropic
    ./libxml2-v2.9.2-fsanitize_fuzzer_entropic -dict=xml.dict -entropic=1 ./tmp_seeds/ seeds/
    ```

#### Run libfuzzer_libxml_vanilla
1. Open a terminal to run fuzzer:
    ```sh
    cd [path to K-Schduler repo]/K-Scheduler/libfuzzer_integration/test_programs/libxml/vanilla 
    # clean fuzzer corpus and other meta data generated by fuzzer
    rm -rf tmp_seeds/ cov_stats  
    mkdir tmp_seeds
    # run libfuzzer_entropic
    ./libxml2-v2.9.2-fsanitize_fuzzer_entropic -dict=xml.dict -entropic=0 ./tmp_seeds/ seeds/
    ```