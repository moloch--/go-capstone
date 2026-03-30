# go-capstone

`go-capstone` is a Go wrapper around the [Capstone](https://www.capstone-engine.org/) disassembler compiled to WebAssembly. It uses [Wazero](https://github.com/tetratelabs/wazero) to run the Capstone wasm side module entirely inside Go and embeds `libcapstone.wasm` into the library with the standard library `embed` package.

The repository also includes a small Cobra-based CLI in `./cli` that acts as both a usable disassembler and an example of calling the library.

## Features

- Pure Go integration through Wazero
- `libcapstone.wasm` is embedded into the package and into binaries that import it
- Idiomatic Go API for opening an engine, setting options, and disassembling bytes
- Versioned Makefile download for the Capstone wasm artifact
- Example CLI built with Cobra

## Requirements

- Go 1.26.1 or newer
- `curl`
- `make`

## Build

The Makefile downloads the Capstone wasm release into `internal/assets/libcapstone.wasm`. That file is then embedded into the Go package at build time.

```bash
make build
```

Useful targets:

- `make wasm` downloads the wasm artifact
- `make deps` downloads Go module dependencies
- `make build` builds the library and CLI
- `make cli` builds `./bin/go-capstone`
- `make test` runs the tests
- `make fmt` formats the code

To update the Capstone wasm version:

```bash
make CAPSTONE_WASM_VERSION=v6.0.0-Alpha7 wasm
```

The download URL is derived from `CAPSTONE_WASM_VERSION` in [`Makefile`](/Users/moloch/git/go-capstone/Makefile).

## Embedded Wasm

The package embeds the wasm payload with:

```go
//go:embed internal/assets/libcapstone.wasm
var embeddedWASM []byte
```

This means consumers of the Go library do not need to ship `libcapstone.wasm` separately at runtime, and the example CLI also carries the wasm in its binary.

## Library Usage

```go
package main

import (
	"context"
	"fmt"
	"log"

	capstone "github.com/moloch--/go-capstone"
)

func main() {
	ctx := context.Background()

	engine, err := capstone.Open(
		ctx,
		capstone.ArchX86,
		capstone.Mode64,
		capstone.WithSyntax(capstone.SyntaxIntel),
	)
	if err != nil {
		log.Fatal(err)
	}
	defer engine.Close(ctx)

	insns, err := engine.Disassemble(ctx, []byte{0x90, 0xc3}, 0)
	if err != nil {
		log.Fatal(err)
	}

	for _, insn := range insns {
		fmt.Printf("%#08x  %-8s %s\n", insn.Address, insn.Mnemonic, insn.OpStr)
	}
}
```

### API Summary

- `Open(ctx, arch, mode, opts...)` creates a disassembly engine
- `WithDetail(bool)` enables or disables Capstone detail mode
- `WithSyntax(syntax)` sets the assembly syntax
- `(*Engine).Disassemble(ctx, code, address)` disassembles all instructions
- `(*Engine).DisassembleCount(ctx, code, address, count)` limits the number of decoded instructions
- `(*Engine).SetDetail(ctx, enabled)` updates detail mode after open
- `(*Engine).SetSyntax(ctx, syntax)` updates syntax after open
- `(*Engine).Close(ctx)` releases the engine and runtime resources

The returned `Instruction` values include:

- `ID`
- `AliasID`
- `Address`
- `Size`
- `Bytes`
- `Mnemonic`
- `OpStr`
- `IsAlias`
- `UsesAliasDetails`
- `Illegal`

## CLI Usage

Build the CLI:

```bash
make cli
```

Disassemble a hex string:

```bash
./bin/go-capstone disasm --arch x86 --mode 64 --hex 90c3
```

Example output:

```text
0x00000000  nop
0x00000001  ret
```

Disassemble bytes from a file:

```bash
./bin/go-capstone disasm --arch x86 --mode 64 --file ./code.bin
```

Supported CLI flags:

- `--arch` selects the architecture
- `--mode` accepts comma-separated mode bits such as `64` or `arm,thumb`
- `--hex` provides hex-encoded bytes
- `--file` reads bytes from a file
- `--syntax` selects `default`, `intel`, `att`, or `masm`
- `--address` sets the starting address
- `--count` limits the number of decoded instructions
- `--detail` enables Capstone detail mode

## Notes

- The implementation treats the Capstone release artifact as an Emscripten side module and wires the necessary imports with Wazero.
- The library currently exposes core instruction metadata cleanly, but it does not yet map architecture-specific `cs_detail` structures into Go types.
- The `./capstone` directory is reference material only and is not imported by this library.
