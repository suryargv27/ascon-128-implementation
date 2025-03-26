from ascon import ascon
import timeit


execution_time = timeit.timeit(ascon, number=10000)
print("Execution time:", execution_time)