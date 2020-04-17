#include "wasmer.h"

typedef struct {
  wasmer_memory_t *memory;
  wasmer_instance_t *instance;
} rego_policy;

rego_policy rego_load_policy(uint8_t *wasmBytes, int wasmlen);

char* rego_evaluate(rego_policy policy, char* input, int inputlen);