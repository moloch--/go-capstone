package capstone

import (
	"bytes"
	"encoding/binary"
	"sort"
)

func buildEnvModule(meta *wasmMetadata, initialPages uint32) []byte {
	var typeSection bytes.Buffer
	var importSection bytes.Buffer
	var memorySection bytes.Buffer
	var tableSection bytes.Buffer
	var globalSection bytes.Buffer
	var exportSection bytes.Buffer
	var elementSection bytes.Buffer

	typeIndices := map[string]uint32{}
	typeOrder := make([]wasmFuncType, 0, len(meta.importedEnvFuncs))
	for _, fn := range meta.importedEnvFuncs {
		key := funcTypeKey(fn.typ)
		if _, ok := typeIndices[key]; ok {
			continue
		}
		typeIndices[key] = uint32(len(typeOrder))
		typeOrder = append(typeOrder, fn.typ)
	}

	writeULEB(&typeSection, uint32(len(typeOrder)))
	for _, typ := range typeOrder {
		typeSection.WriteByte(0x60)
		writeValTypes(&typeSection, typ.params)
		writeValTypes(&typeSection, typ.results)
	}

	writeULEB(&importSection, uint32(len(meta.importedEnvFuncs)))
	for _, fn := range meta.importedEnvFuncs {
		writeName(&importSection, "capstone_host")
		writeName(&importSection, fn.name)
		importSection.WriteByte(0x00)
		writeULEB(&importSection, typeIndices[funcTypeKey(fn.typ)])
	}

	tableSection.WriteByte(0x01)
	tableSection.WriteByte(0x70)
	tableSection.WriteByte(0x00)
	writeULEB(&tableSection, meta.importedTable+meta.tableBase+uint32(len(meta.linkedGOTFuncs)))

	memorySection.WriteByte(0x01)
	memorySection.WriteByte(0x00)
	writeULEB(&memorySection, initialPages)

	stackTop := initialPages * 65536
	writeULEB(&globalSection, 3)
	writeGlobal(&globalSection, true, stackTop)
	writeGlobal(&globalSection, false, 0)
	writeGlobal(&globalSection, false, meta.tableBase)

	writeULEB(&elementSection, 1)
	elementSection.WriteByte(0x00)
	elementSection.WriteByte(0x41)
	writeULEB(&elementSection, 0)
	elementSection.WriteByte(0x0b)
	writeULEB(&elementSection, uint32(len(meta.importedEnvFuncs)))
	for idx := range meta.importedEnvFuncs {
		writeULEB(&elementSection, uint32(idx))
	}

	exportCount := uint32(len(meta.importedEnvFuncs) + 5)
	writeULEB(&exportSection, exportCount)
	for idx, fn := range meta.importedEnvFuncs {
		writeName(&exportSection, fn.name)
		exportSection.WriteByte(0x00)
		writeULEB(&exportSection, uint32(idx))
	}
	writeName(&exportSection, "memory")
	exportSection.WriteByte(0x02)
	writeULEB(&exportSection, 0)
	writeName(&exportSection, "__indirect_function_table")
	exportSection.WriteByte(0x01)
	writeULEB(&exportSection, 0)
	writeName(&exportSection, "__stack_pointer")
	exportSection.WriteByte(0x03)
	writeULEB(&exportSection, 0)
	writeName(&exportSection, "__memory_base")
	exportSection.WriteByte(0x03)
	writeULEB(&exportSection, 1)
	writeName(&exportSection, "__table_base")
	exportSection.WriteByte(0x03)
	writeULEB(&exportSection, 2)

	return buildModule(
		section(1, typeSection.Bytes()),
		section(2, importSection.Bytes()),
		section(4, tableSection.Bytes()),
		section(5, memorySection.Bytes()),
		section(6, globalSection.Bytes()),
		section(7, exportSection.Bytes()),
		section(9, elementSection.Bytes()),
	)
}

func buildLinkerModule(meta *wasmMetadata) []byte {
	var typeSection bytes.Buffer
	var importSection bytes.Buffer
	var elementSection bytes.Buffer

	typeIndices := map[string]uint32{}
	typeOrder := make([]wasmFuncType, 0, len(meta.linkedGOTFuncs))
	for _, name := range meta.linkedGOTFuncs {
		typ := meta.exportedTypes[name]
		key := funcTypeKey(typ)
		if _, ok := typeIndices[key]; ok {
			continue
		}
		typeIndices[key] = uint32(len(typeOrder))
		typeOrder = append(typeOrder, typ)
	}

	writeULEB(&typeSection, uint32(len(typeOrder)))
	for _, typ := range typeOrder {
		typeSection.WriteByte(0x60)
		writeValTypes(&typeSection, typ.params)
		writeValTypes(&typeSection, typ.results)
	}

	writeULEB(&importSection, uint32(len(meta.linkedGOTFuncs)+1))
	writeName(&importSection, "env")
	writeName(&importSection, "__indirect_function_table")
	importSection.WriteByte(0x01)
	importSection.WriteByte(0x70)
	importSection.WriteByte(0x00)
	writeULEB(&importSection, 0)
	for _, name := range meta.linkedGOTFuncs {
		writeName(&importSection, "capstone_core")
		writeName(&importSection, name)
		importSection.WriteByte(0x00)
		writeULEB(&importSection, typeIndices[funcTypeKey(meta.exportedTypes[name])])
	}

	writeULEB(&elementSection, 1)
	elementSection.WriteByte(0x00)
	elementSection.WriteByte(0x41)
	writeULEB(&elementSection, meta.tableBase+meta.importedTable)
	elementSection.WriteByte(0x0b)
	writeULEB(&elementSection, uint32(len(meta.linkedGOTFuncs)))
	for idx := range meta.linkedGOTFuncs {
		writeULEB(&elementSection, uint32(idx))
	}

	return buildModule(
		section(1, typeSection.Bytes()),
		section(2, importSection.Bytes()),
		section(9, elementSection.Bytes()),
	)
}

func buildMutableGlobalModule(names []string) []byte {
	sorted := append([]string(nil), names...)
	sort.Strings(sorted)

	var globalSection bytes.Buffer
	var exportSection bytes.Buffer

	writeULEB(&globalSection, uint32(len(sorted)))
	for range sorted {
		writeGlobal(&globalSection, true, 0)
	}

	writeULEB(&exportSection, uint32(len(sorted)))
	for idx, name := range sorted {
		writeName(&exportSection, name)
		exportSection.WriteByte(0x03)
		writeULEB(&exportSection, uint32(idx))
	}

	return buildModule(
		section(6, globalSection.Bytes()),
		section(7, exportSection.Bytes()),
	)
}

func buildModule(sections ...[]byte) []byte {
	out := []byte{0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00}
	for _, sec := range sections {
		out = append(out, sec...)
	}
	return out
}

func section(id byte, payload []byte) []byte {
	var buf bytes.Buffer
	buf.WriteByte(id)
	writeULEB(&buf, uint32(len(payload)))
	buf.Write(payload)
	return buf.Bytes()
}

func writeULEB(buf *bytes.Buffer, value uint32) {
	for {
		b := byte(value & 0x7f)
		value >>= 7
		if value != 0 {
			b |= 0x80
		}
		buf.WriteByte(b)
		if value == 0 {
			return
		}
	}
}

func writeName(buf *bytes.Buffer, value string) {
	writeULEB(buf, uint32(len(value)))
	buf.WriteString(value)
}

func writeValTypes(buf *bytes.Buffer, values []wasmValType) {
	writeULEB(buf, uint32(len(values)))
	for _, value := range values {
		buf.WriteByte(byte(value))
	}
}

func writeGlobal(buf *bytes.Buffer, mutable bool, value uint32) {
	buf.WriteByte(byte(valTypeI32))
	if mutable {
		buf.WriteByte(0x01)
	} else {
		buf.WriteByte(0x00)
	}
	buf.WriteByte(0x41)
	writeULEB(buf, value)
	buf.WriteByte(0x0b)
}

func funcTypeKey(typ wasmFuncType) string {
	var buf bytes.Buffer
	for _, param := range typ.params {
		buf.WriteByte(byte(param))
	}
	buf.WriteByte('|')
	for _, result := range typ.results {
		buf.WriteByte(byte(result))
	}
	return buf.String()
}

func leBytes32(v uint32) []byte {
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], v)
	return out[:]
}
