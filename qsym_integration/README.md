## K-Scheduler integration on QSYM concolic execution engine
- test_programs: 3 programs with seed corpus reported in our paper.
- build_example: tutorial on how to run K-Scheduler-based QSYM on a binutils program size. 
- afl_qsym_concolic.py and minimizer_qsym_concolic.py: K-Scheduler patchs for QSYM.

## Patch QSYM with K-Scheduler
    ```sh
    sudo cp afl_qsym_concolic.py /usr/local/lib/python2.7/dist-packages/qsym/afl.py
    sudo cp minimizer_qsym_concolic.py /usr/local/lib/python2.7/dist-packages/qsym/minimizer.py
    ```

