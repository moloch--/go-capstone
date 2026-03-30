package capstone

import "context"

type Arch uint32

const (
	ArchARM       Arch = 0
	ArchAArch64   Arch = 1
	ArchSystemZ   Arch = 2
	ArchMIPS      Arch = 3
	ArchX86       Arch = 4
	ArchPPC       Arch = 5
	ArchSPARC     Arch = 6
	ArchXCore     Arch = 7
	ArchM68K      Arch = 8
	ArchTMS320C64 Arch = 9
	ArchM680X     Arch = 10
	ArchEVM       Arch = 11
	ArchMOS65XX   Arch = 12
	ArchWASM      Arch = 13
	ArchBPF       Arch = 14
	ArchRISCV     Arch = 15
	ArchSH        Arch = 16
	ArchTriCore   Arch = 17
	ArchAlpha     Arch = 18
	ArchHPPA      Arch = 19
	ArchLoongArch Arch = 20
	ArchXtensa    Arch = 21
	ArchARC       Arch = 22
)

type Mode uint32

const (
	ModeLittleEndian Mode = 0
	ModeARM          Mode = 0
	Mode16           Mode = 1 << 1
	Mode32           Mode = 1 << 2
	Mode64           Mode = 1 << 3
	ModeThumb        Mode = 1 << 4
	ModeMClass       Mode = 1 << 5
	ModeV8           Mode = 1 << 6
	ModeMicro        Mode = 1 << 4
	ModeMips3        Mode = 1 << 11
	ModeMips32       Mode = Mode32
	ModeMips64       Mode = Mode64
	ModeV9           Mode = 1 << 4
	ModeBigEndian    Mode = 1 << 31
	ModeM680X6301    Mode = 1 << 1
	ModeM680X6800    Mode = 1 << 3
	ModeRISCV32      Mode = 1 << 0
	ModeRISCV64      Mode = 1 << 1
	ModeRISCVC       Mode = 1 << 2
	ModeSH2          Mode = 1 << 1
	ModeSH4          Mode = 1 << 4
	ModeLoongArch32  Mode = 1 << 0
	ModeLoongArch64  Mode = 1 << 1
)

type Syntax uint32

const (
	SyntaxDefault Syntax = 1 << 1
	SyntaxIntel   Syntax = 1 << 2
	SyntaxATT     Syntax = 1 << 3
	SyntaxNoReg   Syntax = 1 << 4
	SyntaxMASM    Syntax = 1 << 5
)

type Error uint32

const (
	ErrOK Error = iota
	ErrMem
	ErrArch
	ErrHandle
	ErrCSH
	ErrMode
	ErrOption
	ErrDetail
	ErrMemSetup
	ErrVersion
	ErrDiet
	ErrSkipData
	ErrX86ATT
	ErrX86Intel
	ErrX86MASM
)

type Instruction struct {
	ID               uint32
	AliasID          uint64
	Address          uint64
	Size             uint16
	Bytes            []byte
	Mnemonic         string
	OpStr            string
	IsAlias          bool
	UsesAliasDetails bool
	Illegal          bool
}

type Option func(*engineOptions)

type engineOptions struct {
	detail bool
	syntax Syntax
}

func WithDetail(enabled bool) Option {
	return func(o *engineOptions) {
		o.detail = enabled
	}
}

func WithSyntax(syntax Syntax) Option {
	return func(o *engineOptions) {
		o.syntax = syntax
	}
}

type Engine struct {
	loader *loader
	handle uint32
	arch   Arch
	mode   Mode
}

func Open(ctx context.Context, arch Arch, mode Mode, opts ...Option) (*Engine, error) {
	options := engineOptions{syntax: SyntaxDefault}
	for _, opt := range opts {
		opt(&options)
	}

	loader, err := newLoader(ctx)
	if err != nil {
		return nil, err
	}

	handle, err := loader.open(ctx, arch, mode)
	if err != nil {
		_ = loader.close(ctx)
		return nil, err
	}

	engine := &Engine{
		loader: loader,
		handle: handle,
		arch:   arch,
		mode:   mode,
	}

	if options.detail {
		if err := engine.SetDetail(ctx, true); err != nil {
			_ = engine.Close(ctx)
			return nil, err
		}
	}
	if options.syntax != 0 && options.syntax != SyntaxDefault {
		if err := engine.SetSyntax(ctx, options.syntax); err != nil {
			_ = engine.Close(ctx)
			return nil, err
		}
	}

	return engine, nil
}

func (e *Engine) SetDetail(ctx context.Context, enabled bool) error {
	value := uint32(0)
	if enabled {
		value = 1
	}
	return e.loader.setOption(ctx, e.handle, 2, value)
}

func (e *Engine) SetSyntax(ctx context.Context, syntax Syntax) error {
	if syntax == 0 {
		syntax = SyntaxDefault
	}
	return e.loader.setOption(ctx, e.handle, 1, uint32(syntax))
}

func (e *Engine) Disassemble(ctx context.Context, code []byte, address uint64) ([]Instruction, error) {
	return e.DisassembleCount(ctx, code, address, 0)
}

func (e *Engine) DisassembleCount(ctx context.Context, code []byte, address uint64, count uint32) ([]Instruction, error) {
	return e.loader.disassemble(ctx, e.handle, code, address, count)
}

func (e *Engine) Close(ctx context.Context) error {
	if e.loader == nil {
		return nil
	}
	err := e.loader.closeHandle(ctx, e.handle)
	if closeErr := e.loader.close(ctx); err == nil {
		err = closeErr
	}
	e.loader = nil
	e.handle = 0
	return err
}
