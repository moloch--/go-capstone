package capstone

import (
	"errors"
	"fmt"
	"sort"
)

type wasmValType byte

const (
	valTypeI32 wasmValType = 0x7f
	valTypeI64 wasmValType = 0x7e
)

type wasmFuncType struct {
	params  []wasmValType
	results []wasmValType
}

type wasmMetadata struct {
	staticMemorySize uint32
	importedMemory   uint32
	importedTable    uint32
	tableBase        uint32
	importedEnvFuncs []envFuncImport
	importedGOTMem   []string
	importedGOTFunc  []string
	linkedGOTFuncs   []string
	exportedFuncs    map[string]uint32
	exportedTypes    map[string]wasmFuncType
	exportedGlobals  map[string]struct{}
	tableIndexByFunc map[uint32]uint32
}

type envFuncImport struct {
	name string
	typ  wasmFuncType
}

func (m *wasmMetadata) tableIndexForExport(name string) (uint32, bool) {
	funcIndex, ok := m.exportedFuncs[name]
	if !ok {
		return 0, false
	}
	tableIndex, ok := m.tableIndexByFunc[funcIndex]
	return tableIndex + m.tableBase, ok
}

func (m *wasmMetadata) envFunctionPointer(name string) (uint32, bool) {
	if name == "vsnprintf" {
		name = "snprintf"
	}
	for idx, fn := range m.importedEnvFuncs {
		if fn.name == name {
			return uint32(idx), true
		}
	}
	return 0, false
}

func parseWASMMetadata(source []byte) (*wasmMetadata, error) {
	if len(source) < 8 || string(source[:4]) != "\x00asm" {
		return nil, errors.New("invalid wasm header")
	}

	reader := wasmReader{buf: source, off: 8}
	meta := &wasmMetadata{
		exportedFuncs:    map[string]uint32{},
		exportedTypes:    map[string]wasmFuncType{},
		exportedGlobals:  map[string]struct{}{},
		tableIndexByFunc: map[uint32]uint32{},
	}

	var types []wasmFuncType
	var importedGlobals int
	var importedFuncs uint32
	var definedFuncTypes []uint32

	for reader.off < len(source) {
		sectionID, err := reader.byte()
		if err != nil {
			return nil, err
		}
		sectionSize, err := reader.uleb()
		if err != nil {
			return nil, err
		}
		sectionEnd := reader.off + int(sectionSize)
		if sectionEnd > len(source) {
			return nil, errors.New("truncated wasm section")
		}

		switch sectionID {
		case 0:
			name, err := reader.name()
			if err != nil {
				return nil, err
			}
			if name == "dylink.0" {
				if err := parseDylink(source[reader.off:sectionEnd], meta); err != nil {
					return nil, err
				}
			}
			reader.off = sectionEnd
		case 1:
			count, err := reader.uleb()
			if err != nil {
				return nil, err
			}
			types = make([]wasmFuncType, 0, count)
			for i := uint32(0); i < count; i++ {
				form, err := reader.byte()
				if err != nil {
					return nil, err
				}
				if form != 0x60 {
					return nil, fmt.Errorf("unexpected function type form %#x", form)
				}
				params, err := reader.valTypes()
				if err != nil {
					return nil, err
				}
				results, err := reader.valTypes()
				if err != nil {
					return nil, err
				}
				types = append(types, wasmFuncType{params: params, results: results})
			}
		case 2:
			count, err := reader.uleb()
			if err != nil {
				return nil, err
			}
			for i := uint32(0); i < count; i++ {
				moduleName, err := reader.name()
				if err != nil {
					return nil, err
				}
				name, err := reader.name()
				if err != nil {
					return nil, err
				}
				kind, err := reader.byte()
				if err != nil {
					return nil, err
				}
				switch kind {
				case 0:
					typeIndex, err := reader.uleb()
					if err != nil {
						return nil, err
					}
					importedFuncs++
					if moduleName == "env" {
						meta.importedEnvFuncs = append(meta.importedEnvFuncs, envFuncImport{name: name, typ: types[typeIndex]})
					}
				case 1:
					if _, err := reader.uleb(); err != nil {
						return nil, err
					}
					min, err := readLimits(&reader)
					if err != nil {
						return nil, err
					}
					if moduleName == "env" && name == "__indirect_function_table" {
						meta.importedTable = min
					}
				case 2:
					min, err := readLimits(&reader)
					if err != nil {
						return nil, err
					}
					if moduleName == "env" && name == "memory" {
						meta.importedMemory = min
					}
				case 3:
					if _, err := reader.byte(); err != nil {
						return nil, err
					}
					if _, err := reader.byte(); err != nil {
						return nil, err
					}
					if moduleName == "GOT.mem" {
						meta.importedGOTMem = append(meta.importedGOTMem, name)
					}
					if moduleName == "GOT.func" {
						meta.importedGOTFunc = append(meta.importedGOTFunc, name)
					}
					importedGlobals++
				default:
					return nil, fmt.Errorf("unsupported import kind %d", kind)
				}
			}
		case 7:
			count, err := reader.uleb()
			if err != nil {
				return nil, err
			}
			for i := uint32(0); i < count; i++ {
				name, err := reader.name()
				if err != nil {
					return nil, err
				}
				kind, err := reader.byte()
				if err != nil {
					return nil, err
				}
				index, err := reader.uleb()
				if err != nil {
					return nil, err
				}
				switch kind {
				case 0:
					meta.exportedFuncs[name] = index
					if index >= importedFuncs {
						defIdx := index - importedFuncs
						if int(defIdx) < len(definedFuncTypes) {
							meta.exportedTypes[name] = types[definedFuncTypes[defIdx]]
						}
					}
				case 3:
					meta.exportedGlobals[name] = struct{}{}
				}
			}
		case 3:
			count, err := reader.uleb()
			if err != nil {
				return nil, err
			}
			definedFuncTypes = make([]uint32, 0, count)
			for i := uint32(0); i < count; i++ {
				typeIndex, err := reader.uleb()
				if err != nil {
					return nil, err
				}
				definedFuncTypes = append(definedFuncTypes, typeIndex)
			}
		case 9:
			count, err := reader.uleb()
			if err != nil {
				return nil, err
			}
			for i := uint32(0); i < count; i++ {
				flags, err := reader.uleb()
				if err != nil {
					return nil, err
				}
				if flags != 0 {
					return nil, fmt.Errorf("unsupported element segment flags %d", flags)
				}
				offsetGlobal, err := parseOffsetGlobal(&reader)
				if err != nil {
					return nil, err
				}
				countFuncs, err := reader.uleb()
				if err != nil {
					return nil, err
				}
				base := uint32(0)
				if offsetGlobal != 2 {
					base = 0
				}
				for j := uint32(0); j < countFuncs; j++ {
					funcIndex, err := reader.uleb()
					if err != nil {
						return nil, err
					}
					meta.tableIndexByFunc[funcIndex] = base + j
				}
			}
		default:
			reader.off = sectionEnd
		}

		reader.off = sectionEnd
	}

	sort.Strings(meta.importedGOTMem)
	sort.Strings(meta.importedGOTFunc)
	meta.tableBase = uint32(len(meta.importedEnvFuncs))
	for _, name := range meta.importedGOTFunc {
		if _, ok := meta.envFunctionPointer(name); ok {
			continue
		}
		if _, ok := meta.exportedFuncs[name]; ok {
			meta.linkedGOTFuncs = append(meta.linkedGOTFuncs, name)
		}
	}

	if meta.staticMemorySize == 0 {
		meta.staticMemorySize = meta.importedMemory * 65536
	}
	return meta, nil
}

func (m *wasmMetadata) linkedFunctionPointer(name string) (uint32, bool) {
	base := m.tableBase + m.importedTable
	for idx, fn := range m.linkedGOTFuncs {
		if fn == name {
			return base + uint32(idx), true
		}
	}
	return 0, false
}

func parseDylink(data []byte, meta *wasmMetadata) error {
	reader := wasmReader{buf: data}
	for reader.off < len(data) {
		subsectionType, err := reader.byte()
		if err != nil {
			return err
		}
		subsectionSize, err := reader.uleb()
		if err != nil {
			return err
		}
		end := reader.off + int(subsectionSize)
		if end > len(data) {
			return errors.New("truncated dylink subsection")
		}
		if subsectionType == 1 {
			memSize, err := reader.uleb()
			if err != nil {
				return err
			}
			if _, err := reader.uleb(); err != nil {
				return err
			}
			if _, err := reader.uleb(); err != nil {
				return err
			}
			if _, err := reader.uleb(); err != nil {
				return err
			}
			if reader.off < end {
				if _, err := reader.uleb(); err != nil {
					return err
				}
			}
			meta.staticMemorySize = memSize
		}
		reader.off = end
	}
	return nil
}

func readLimits(reader *wasmReader) (uint32, error) {
	flags, err := reader.byte()
	if err != nil {
		return 0, err
	}
	min, err := reader.uleb()
	if err != nil {
		return 0, err
	}
	if flags&0x01 != 0 {
		if _, err := reader.uleb(); err != nil {
			return 0, err
		}
	}
	return min, nil
}

func parseOffsetGlobal(reader *wasmReader) (uint32, error) {
	op, err := reader.byte()
	if err != nil {
		return 0, err
	}
	if op != 0x23 {
		return 0, fmt.Errorf("unsupported offset opcode %#x", op)
	}
	idx, err := reader.uleb()
	if err != nil {
		return 0, err
	}
	end, err := reader.byte()
	if err != nil {
		return 0, err
	}
	if end != 0x0b {
		return 0, fmt.Errorf("unterminated offset expr %#x", end)
	}
	return idx, nil
}

type wasmReader struct {
	buf []byte
	off int
}

func (r *wasmReader) byte() (byte, error) {
	if r.off >= len(r.buf) {
		return 0, errors.New("unexpected EOF")
	}
	b := r.buf[r.off]
	r.off++
	return b, nil
}

func (r *wasmReader) uleb() (uint32, error) {
	var result uint32
	var shift uint32
	for {
		b, err := r.byte()
		if err != nil {
			return 0, err
		}
		result |= uint32(b&0x7f) << shift
		if b&0x80 == 0 {
			return result, nil
		}
		shift += 7
		if shift > 35 {
			return 0, errors.New("invalid leb128")
		}
	}
}

func (r *wasmReader) name() (string, error) {
	length, err := r.uleb()
	if err != nil {
		return "", err
	}
	end := r.off + int(length)
	if end > len(r.buf) {
		return "", errors.New("truncated wasm string")
	}
	value := string(r.buf[r.off:end])
	r.off = end
	return value, nil
}

func (r *wasmReader) valTypes() ([]wasmValType, error) {
	count, err := r.uleb()
	if err != nil {
		return nil, err
	}
	out := make([]wasmValType, 0, count)
	for i := uint32(0); i < count; i++ {
		b, err := r.byte()
		if err != nil {
			return nil, err
		}
		out = append(out, wasmValType(b))
	}
	return out, nil
}
