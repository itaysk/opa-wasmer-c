example.wasm: example.rego
	opa build -d example.rego 'x = data' -o example.wasm

demo: demo.c opa-wasmer-c.c example.wasm
	clang demo.c opa-wasmer-c.c -o demo -I ./wasmer/include -L ./wasmer/lib -l wasmer -rpath ./wasmer/lib

clean:
	rm ./demo ./example.wasm || true