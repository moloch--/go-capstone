package capstone

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"strings"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

// embeddedWASM is compiled into the library with the Go stdlib embed package.
// Any binary importing this package, including ./cli, carries the wasm payload
// with it and does not need libcapstone.wasm at runtime.
//
//go:embed internal/assets/libcapstone.wasm
var embeddedWASM []byte

const (
	csInsnStride       = 256
	csInsnOffsetID     = 0
	csInsnOffsetAlias  = 8
	csInsnOffsetAddr   = 16
	csInsnOffsetSize   = 24
	csInsnOffsetBytes  = 26
	csInsnOffsetMnem   = 50
	csInsnOffsetOpStr  = 82
	csInsnOffsetAliasB = 242
	csInsnOffsetUseB   = 243
	csInsnOffsetIllB   = 244
)

type loader struct {
	runtime  wazero.Runtime
	host     *hostState
	meta     *wasmMetadata
	module   api.Module
	csOpen   api.Function
	csClose  api.Function
	csOption api.Function
	csErrno  api.Function
	csStrErr api.Function
	csDisasm api.Function
	csFree   api.Function
	gotMem   map[string]api.MutableGlobal
	gotFunc  map[string]api.MutableGlobal
}

func newLoader(ctx context.Context) (*loader, error) {
	if len(embeddedWASM) < 8 || string(embeddedWASM[:4]) != "\x00asm" {
		return nil, errors.New("embedded capstone wasm is missing or invalid; run `make wasm` and rebuild")
	}

	meta, err := parseWASMMetadata(embeddedWASM)
	if err != nil {
		return nil, fmt.Errorf("parse capstone wasm metadata: %w", err)
	}

	runtime := wazero.NewRuntime(ctx)
	host := newHostState(meta)
	if err := host.instantiate(ctx, runtime, meta); err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}

	envModule, err := runtime.InstantiateWithConfig(ctx, buildEnvModule(meta, host.initialMemoryPages()), wazero.NewModuleConfig().WithName("env").WithStartFunctions())
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate env module: %w", err)
	}
	host.bindMemory(envModule.Memory())

	gotMemModule, err := runtime.InstantiateWithConfig(ctx, buildMutableGlobalModule(meta.importedGOTMem), wazero.NewModuleConfig().WithName("GOT.mem").WithStartFunctions())
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate GOT.mem module: %w", err)
	}
	gotFuncModule, err := runtime.InstantiateWithConfig(ctx, buildMutableGlobalModule(meta.importedGOTFunc), wazero.NewModuleConfig().WithName("GOT.func").WithStartFunctions())
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate GOT.func module: %w", err)
	}

	module, err := runtime.InstantiateWithConfig(ctx, embeddedWASM, wazero.NewModuleConfig().WithName("capstone_core").WithStartFunctions())
	if err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate capstone module: %w", err)
	}
	if _, err := runtime.InstantiateWithConfig(ctx, buildLinkerModule(meta), wazero.NewModuleConfig().WithName("capstone_linker").WithStartFunctions()); err != nil {
		_ = runtime.Close(ctx)
		return nil, fmt.Errorf("instantiate capstone linker module: %w", err)
	}

	l := &loader{
		runtime:  runtime,
		host:     host,
		meta:     meta,
		module:   module,
		csOpen:   module.ExportedFunction("cs_open"),
		csClose:  module.ExportedFunction("cs_close"),
		csOption: module.ExportedFunction("cs_option"),
		csErrno:  module.ExportedFunction("cs_errno"),
		csStrErr: module.ExportedFunction("cs_strerror"),
		csDisasm: module.ExportedFunction("cs_disasm"),
		csFree:   module.ExportedFunction("cs_free"),
		gotMem:   exportedMutableGlobals(gotMemModule, meta.importedGOTMem),
		gotFunc:  exportedMutableGlobals(gotFuncModule, meta.importedGOTFunc),
	}
	if l.csOpen == nil || l.csClose == nil || l.csOption == nil || l.csErrno == nil || l.csStrErr == nil || l.csDisasm == nil || l.csFree == nil {
		_ = runtime.Close(ctx)
		return nil, errors.New("capstone exports are incomplete")
	}

	if err := l.relocate(ctx); err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}
	if err := l.initializeMemoryHooks(ctx); err != nil {
		_ = runtime.Close(ctx)
		return nil, err
	}

	return l, nil
}

func exportedMutableGlobals(module api.Module, names []string) map[string]api.MutableGlobal {
	result := make(map[string]api.MutableGlobal, len(names))
	for _, name := range names {
		if g, ok := module.ExportedGlobal(name).(api.MutableGlobal); ok {
			result[name] = g
		}
	}
	return result
}

func (l *loader) relocate(ctx context.Context) error {
	for _, name := range l.meta.importedGOTMem {
		target := l.module.ExportedGlobal(name)
		dst := l.gotMem[name]
		if target == nil || dst == nil {
			continue
		}
		dst.Set(target.Get())
	}

	for _, name := range l.meta.importedGOTFunc {
		tableIndex, ok := l.meta.envFunctionPointer(name)
		if !ok {
			tableIndex, ok = l.meta.linkedFunctionPointer(name)
		}
		dst := l.gotFunc[name]
		if !ok || dst == nil {
			continue
		}
		dst.Set(uint64(tableIndex))
	}

	if fn := l.module.ExportedFunction("__wasm_apply_data_relocs"); fn != nil {
		if _, err := fn.Call(ctx); err != nil {
			return fmt.Errorf("apply capstone data relocs: %w", err)
		}
	}
	if fn := l.module.ExportedFunction("__wasm_call_ctors"); fn != nil {
		if _, err := fn.Call(ctx); err != nil {
			return fmt.Errorf("run capstone ctors: %w", err)
		}
	}

	for _, name := range []string{
		"cs_arch_register_arm",
		"cs_arch_register_aarch64",
		"cs_arch_register_mips",
		"cs_arch_register_x86",
		"cs_arch_register_powerpc",
		"cs_arch_register_sparc",
		"cs_arch_register_systemz",
		"cs_arch_register_xcore",
		"cs_arch_register_m68k",
		"cs_arch_register_tms320c64x",
		"cs_arch_register_m680x",
		"cs_arch_register_evm",
		"cs_arch_register_mos65xx",
		"cs_arch_register_wasm",
		"cs_arch_register_bpf",
		"cs_arch_register_riscv",
		"cs_arch_register_sh",
		"cs_arch_register_tricore",
		"cs_arch_register_alpha",
		"cs_arch_register_loongarch",
		"cs_arch_register_arc",
	} {
		if fn := l.module.ExportedFunction(name); fn != nil {
			if _, err := fn.Call(ctx); err != nil {
				return fmt.Errorf("initialize %s: %w", name, err)
			}
		}
	}

	return nil
}

func (l *loader) initializeMemoryHooks(ctx context.Context) error {
	memOptPtr, err := l.host.alloc(20)
	if err != nil {
		return err
	}
	defer l.host.free(memOptPtr)

	for idx, name := range []string{"malloc", "calloc", "realloc", "free", "snprintf"} {
		ptr, ok := l.meta.envFunctionPointer(name)
		if !ok {
			return fmt.Errorf("missing env function pointer for %s", name)
		}
		if !l.host.memory.WriteUint32Le(memOptPtr+uint32(idx*4), ptr) {
			return fmt.Errorf("write memory hook for %s", name)
		}
	}

	results, err := l.csOption.Call(ctx, 0, 4, uint64(memOptPtr))
	if err != nil {
		return fmt.Errorf("initialize capstone memory hooks: %w", err)
	}
	if len(results) != 1 || Error(results[0]) != ErrOK {
		return fmt.Errorf("initialize capstone memory hooks: %w", l.lastError(ctx, 0, Error(results[0])))
	}
	return nil
}

func (l *loader) open(ctx context.Context, arch Arch, mode Mode) (uint32, error) {
	handlePtr, err := l.host.alloc(uint32(4))
	if err != nil {
		return 0, err
	}
	defer l.host.free(handlePtr)

	results, err := l.csOpen.Call(ctx, uint64(arch), uint64(mode), uint64(handlePtr))
	if err != nil {
		return 0, fmt.Errorf("cs_open trap: %w", err)
	}
	if len(results) != 1 || Error(results[0]) != ErrOK {
		return 0, fmt.Errorf("cs_open failed for arch=%d mode=%#x: %w", arch, mode, l.lastError(ctx, 0, Error(results[0])))
	}

	handle, ok := l.host.memory.ReadUint32Le(handlePtr)
	if !ok || handle == 0 {
		return 0, errors.New("cs_open returned an empty handle")
	}
	return handle, nil
}

func (l *loader) closeHandle(ctx context.Context, handle uint32) error {
	if handle == 0 {
		return nil
	}
	handlePtr, err := l.host.alloc(uint32(4))
	if err != nil {
		return err
	}
	defer l.host.free(handlePtr)

	if !l.host.memory.WriteUint32Le(handlePtr, handle) {
		return errors.New("write close handle pointer")
	}
	results, err := l.csClose.Call(ctx, uint64(handlePtr))
	if err != nil {
		return fmt.Errorf("cs_close trap: %w", err)
	}
	if len(results) == 1 && Error(results[0]) != ErrOK {
		return l.lastError(ctx, handle, Error(results[0]))
	}
	return nil
}

func (l *loader) setOption(ctx context.Context, handle uint32, opt uint32, value uint32) error {
	results, err := l.csOption.Call(ctx, uint64(handle), uint64(opt), uint64(value))
	if err != nil {
		return fmt.Errorf("cs_option trap: %w", err)
	}
	if len(results) != 1 || Error(results[0]) != ErrOK {
		return l.lastError(ctx, handle, Error(results[0]))
	}
	return nil
}

func (l *loader) disassemble(ctx context.Context, handle uint32, code []byte, address uint64, count uint32) ([]Instruction, error) {
	codePtr, err := l.host.allocBytes(code)
	if err != nil {
		return nil, err
	}
	defer l.host.free(codePtr)

	insnPtrPtr, err := l.host.alloc(uint32(4))
	if err != nil {
		return nil, err
	}
	defer l.host.free(insnPtrPtr)

	results, err := l.csDisasm.Call(ctx, uint64(handle), uint64(codePtr), uint64(len(code)), address, uint64(count), uint64(insnPtrPtr))
	if err != nil {
		return nil, fmt.Errorf("cs_disasm trap: %w", err)
	}
	if len(results) != 1 {
		return nil, errors.New("cs_disasm returned an unexpected result set")
	}

	disassembled := uint32(results[0])
	if disassembled == 0 {
		return nil, fmt.Errorf("cs_disasm failed for handle %#x: %w", handle, l.lastError(ctx, handle, 0))
	}

	basePtr, ok := l.host.memory.ReadUint32Le(insnPtrPtr)
	if !ok || basePtr == 0 {
		return nil, errors.New("cs_disasm returned a nil instruction pointer")
	}

	instructions := make([]Instruction, 0, disassembled)
	for i := uint32(0); i < disassembled; i++ {
		insnPtr := basePtr + i*csInsnStride
		insn, err := l.readInstruction(insnPtr)
		if err != nil {
			_, _ = l.csFree.Call(ctx, uint64(basePtr), uint64(disassembled))
			return nil, err
		}
		instructions = append(instructions, insn)
	}

	if _, err := l.csFree.Call(ctx, uint64(basePtr), uint64(disassembled)); err != nil {
		return nil, fmt.Errorf("cs_free trap: %w", err)
	}

	return instructions, nil
}

func (l *loader) readInstruction(ptr uint32) (Instruction, error) {
	mem := l.host.memory

	id, ok := mem.ReadUint32Le(ptr + csInsnOffsetID)
	if !ok {
		return Instruction{}, errors.New("read instruction id")
	}
	aliasID, ok := mem.ReadUint64Le(ptr + csInsnOffsetAlias)
	if !ok {
		return Instruction{}, errors.New("read instruction alias id")
	}
	address, ok := mem.ReadUint64Le(ptr + csInsnOffsetAddr)
	if !ok {
		return Instruction{}, errors.New("read instruction address")
	}
	size, ok := mem.ReadUint16Le(ptr + csInsnOffsetSize)
	if !ok {
		return Instruction{}, errors.New("read instruction size")
	}
	rawBytes, ok := mem.Read(ptr+csInsnOffsetBytes, 24)
	if !ok {
		return Instruction{}, errors.New("read instruction bytes")
	}
	mnemonic, err := readCStringFixed(mem, ptr+csInsnOffsetMnem, 32)
	if err != nil {
		return Instruction{}, err
	}
	opStr, err := readCStringFixed(mem, ptr+csInsnOffsetOpStr, 160)
	if err != nil {
		return Instruction{}, err
	}
	isAlias, ok := mem.ReadByte(ptr + csInsnOffsetAliasB)
	if !ok {
		return Instruction{}, errors.New("read instruction alias flag")
	}
	usesAlias, ok := mem.ReadByte(ptr + csInsnOffsetUseB)
	if !ok {
		return Instruction{}, errors.New("read instruction alias-detail flag")
	}
	illegal, ok := mem.ReadByte(ptr + csInsnOffsetIllB)
	if !ok {
		return Instruction{}, errors.New("read instruction illegal flag")
	}

	out := Instruction{
		ID:               id,
		AliasID:          aliasID,
		Address:          address,
		Size:             size,
		Bytes:            append([]byte(nil), rawBytes[:size]...),
		Mnemonic:         mnemonic,
		OpStr:            opStr,
		IsAlias:          isAlias != 0,
		UsesAliasDetails: usesAlias != 0,
		Illegal:          illegal != 0,
	}
	return out, nil
}

func readCStringFixed(mem api.Memory, ptr uint32, size uint32) (string, error) {
	buf, ok := mem.Read(ptr, size)
	if !ok {
		return "", fmt.Errorf("read string at %#x", ptr)
	}
	if idx := bytesIndex(buf, 0); idx >= 0 {
		buf = buf[:idx]
	}
	return string(buf), nil
}

func bytesIndex(buf []byte, needle byte) int {
	for i, b := range buf {
		if b == needle {
			return i
		}
	}
	return -1
}

func (l *loader) lastError(ctx context.Context, handle uint32, fallback Error) error {
	code := fallback
	if handle != 0 && l.csErrno != nil {
		if results, err := l.csErrno.Call(ctx, uint64(handle)); err == nil && len(results) == 1 {
			code = Error(results[0])
		}
	}
	message := fmt.Sprintf("capstone error %d", code)
	if l.csStrErr != nil {
		if results, err := l.csStrErr.Call(ctx, uint64(code)); err == nil && len(results) == 1 && results[0] != 0 {
			if s, readErr := l.host.readCString(uint32(results[0])); readErr == nil && strings.TrimSpace(s) != "" {
				message = s
			}
		}
	}
	return fmt.Errorf("%s", message)
}

func (l *loader) close(ctx context.Context) error {
	if l.runtime == nil {
		return nil
	}
	err := l.runtime.Close(ctx)
	l.runtime = nil
	return err
}
