#include <stdio.h>
#include <string.h>
#include "opa-wasmer-c.h"
  
int main(int argc, char *argv[]) {
  if (argc != 3) {
    printf("usage: demo <compiled-policy> <input>");
    printf("example: demo policy.wasm '{\"foo\":1}'"); 
  }
  char* filePath=argv[1];
  char* input=argv[2];

  FILE *wasmFile = fopen(filePath, "r");
  if (wasmFile == NULL) {
    fprintf(stderr, "cannot open the specified wasm module file: %s", filePath);
  }
  fseek(wasmFile, 0, SEEK_END);
  long wasmlen = ftell(wasmFile);
  uint8_t *wasmBytes = malloc(wasmlen);
  fseek(wasmFile, 0, SEEK_SET);
  fread(wasmBytes, 1, wasmlen, wasmFile);
  fclose(wasmFile);
  

  rego_policy policy = rego_load_policy(wasmBytes, wasmlen);
  char* res = rego_evaluate(policy, input, strlen(input));
  printf("%s", res);
  // TODO: free allocated!!!
  return 0;
}