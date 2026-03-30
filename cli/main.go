package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"
	"strings"

	capstone "github.com/moloch--/go-capstone"
	"github.com/spf13/cobra"
)

func main() {
	if err := newRootCmd().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func newRootCmd() *cobra.Command {
	var (
		archFlag   string
		modeFlag   string
		hexFlag    string
		fileFlag   string
		syntaxFlag string
		address    uint64
		count      uint32
		detail     bool
	)

	cmd := &cobra.Command{
		Use:   "go-capstone",
		Short: "Disassemble bytes with the go-capstone Wazero wrapper",
	}

	disasmCmd := &cobra.Command{
		Use:   "disasm",
		Short: "Disassemble a hex string or file",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			arch, err := parseArch(archFlag)
			if err != nil {
				return err
			}
			mode, err := parseMode(modeFlag)
			if err != nil {
				return err
			}
			syntax, err := parseSyntax(syntaxFlag)
			if err != nil {
				return err
			}
			code, err := readInput(hexFlag, fileFlag)
			if err != nil {
				return err
			}

			engine, err := capstone.Open(ctx, arch, mode, capstone.WithSyntax(syntax), capstone.WithDetail(detail))
			if err != nil {
				return err
			}
			defer engine.Close(ctx)

			insns, err := engine.DisassembleCount(ctx, code, address, count)
			if err != nil {
				return err
			}

			for _, insn := range insns {
				if insn.OpStr == "" {
					fmt.Printf("%#08x  %-8s\n", insn.Address, insn.Mnemonic)
					continue
				}
				fmt.Printf("%#08x  %-8s %s\n", insn.Address, insn.Mnemonic, insn.OpStr)
			}
			return nil
		},
	}

	disasmCmd.Flags().StringVar(&archFlag, "arch", "x86", "target architecture")
	disasmCmd.Flags().StringVar(&modeFlag, "mode", "64", "comma-separated mode bits, for example: 64 or arm,thumb")
	disasmCmd.Flags().StringVar(&hexFlag, "hex", "", "hex-encoded instruction bytes")
	disasmCmd.Flags().StringVar(&fileFlag, "file", "", "read instruction bytes from a file")
	disasmCmd.Flags().StringVar(&syntaxFlag, "syntax", "default", "assembly syntax: default,intel,att,masm")
	disasmCmd.Flags().Uint64Var(&address, "address", 0, "starting address")
	disasmCmd.Flags().Uint32Var(&count, "count", 0, "maximum number of instructions to decode, 0 means all")
	disasmCmd.Flags().BoolVar(&detail, "detail", false, "enable Capstone detail mode")
	cmd.AddCommand(disasmCmd)

	return cmd
}

func readInput(hexFlag, fileFlag string) ([]byte, error) {
	switch {
	case hexFlag != "":
		clean := strings.ReplaceAll(strings.TrimSpace(hexFlag), " ", "")
		return hex.DecodeString(clean)
	case fileFlag != "":
		return os.ReadFile(fileFlag)
	default:
		return nil, fmt.Errorf("one of --hex or --file is required")
	}
}

func parseArch(value string) (capstone.Arch, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "arm":
		return capstone.ArchARM, nil
	case "aarch64", "arm64":
		return capstone.ArchAArch64, nil
	case "mips":
		return capstone.ArchMIPS, nil
	case "x86":
		return capstone.ArchX86, nil
	case "ppc", "powerpc":
		return capstone.ArchPPC, nil
	case "riscv":
		return capstone.ArchRISCV, nil
	case "wasm":
		return capstone.ArchWASM, nil
	default:
		return 0, fmt.Errorf("unsupported arch %q", value)
	}
}

func parseMode(value string) (capstone.Mode, error) {
	var mode capstone.Mode
	for _, part := range strings.Split(value, ",") {
		switch strings.ToLower(strings.TrimSpace(part)) {
		case "", "0":
		case "16":
			mode |= capstone.Mode16
		case "32":
			mode |= capstone.Mode32
		case "64":
			mode |= capstone.Mode64
		case "arm":
			mode |= capstone.ModeARM
		case "thumb":
			mode |= capstone.ModeThumb
		case "big":
			mode |= capstone.ModeBigEndian
		case "little":
			mode |= capstone.ModeLittleEndian
		case "riscv32":
			mode |= capstone.ModeRISCV32
		case "riscv64":
			mode |= capstone.ModeRISCV64
		case "riscvc":
			mode |= capstone.ModeRISCVC
		default:
			num, err := strconv.ParseUint(part, 0, 32)
			if err != nil {
				return 0, fmt.Errorf("unknown mode %q", part)
			}
			mode |= capstone.Mode(num)
		}
	}
	return mode, nil
}

func parseSyntax(value string) (capstone.Syntax, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "default":
		return capstone.SyntaxDefault, nil
	case "intel":
		return capstone.SyntaxIntel, nil
	case "att":
		return capstone.SyntaxATT, nil
	case "masm":
		return capstone.SyntaxMASM, nil
	default:
		return 0, fmt.Errorf("unsupported syntax %q", value)
	}
}
