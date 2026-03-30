package capstone

import (
	"context"
	"testing"
)

func TestDisassembleX86(t *testing.T) {
	if len(embeddedWASM) < 8 || string(embeddedWASM[:4]) != "\x00asm" {
		t.Skip("capstone wasm is not available; run `make wasm` first")
	}

	ctx := context.Background()
	engine, err := Open(ctx, ArchX86, Mode64)
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	defer func() {
		if closeErr := engine.Close(ctx); closeErr != nil {
			t.Fatalf("close engine: %v", closeErr)
		}
	}()

	insns, err := engine.Disassemble(ctx, []byte{0x90, 0xc3}, 0)
	if err != nil {
		t.Fatalf("disassemble: %v", err)
	}
	if len(insns) != 2 {
		t.Fatalf("expected 2 instructions, got %d", len(insns))
	}
	if insns[0].Mnemonic != "nop" {
		t.Fatalf("expected first instruction to be nop, got %q", insns[0].Mnemonic)
	}
	if insns[1].Mnemonic != "ret" {
		t.Fatalf("expected second instruction to be ret, got %q", insns[1].Mnemonic)
	}
}
