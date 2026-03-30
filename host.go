package capstone

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/tetratelabs/wazero"
	"github.com/tetratelabs/wazero/api"
)

type hostState struct {
	mu          sync.Mutex
	memory      api.Memory
	next        uint32
	heapStart   uint32
	heapLimit   uint32
	allocs      map[uint32]uint32
	freeList    []memoryBlock
	staticBytes uint32
	pages       uint32
}

type memoryBlock struct {
	ptr  uint32
	size uint32
}

func newHostState(meta *wasmMetadata) *hostState {
	const minPages = 1024
	pages := meta.importedMemory + 256
	if pages < minPages {
		pages = minPages
	}
	stackReserve := uint32(8 * 1024 * 1024)
	stackTop := pages * 65536
	heapStart := alignUp(meta.staticMemorySize, 16)
	heapLimit := stackTop - stackReserve
	return &hostState{
		next:        heapStart,
		heapStart:   heapStart,
		heapLimit:   heapLimit,
		allocs:      map[uint32]uint32{},
		staticBytes: meta.staticMemorySize,
		pages:       pages,
	}
}

func (h *hostState) initialMemoryPages() uint32 {
	return h.pages
}

func (h *hostState) bindMemory(memory api.Memory) {
	h.memory = memory
}

func (h *hostState) instantiate(ctx context.Context, runtime wazero.Runtime, meta *wasmMetadata) error {
	builder := runtime.NewHostModuleBuilder("capstone_host")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, dst, src, n uint32) uint32 {
		return h.fnStrncpy(dst, src, n)
	}).Export("strncpy")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr uint32) uint32 {
		return h.fnStrlen(ptr)
	}).Export("strlen")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, dst, size, format, args uint32) uint32 {
		return h.fnSnprintf(dst, size, format, args)
	}).Export("snprintf")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, size uint32) uint32 {
		ptr, _ := h.alloc(size)
		return ptr
	}).Export("malloc")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, count, size uint32) uint32 {
		return h.fnCalloc(count, size)
	}).Export("calloc")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, size uint32) uint32 {
		return h.fnRealloc(ptr, size)
	}).Export("realloc")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr uint32) {
		h.free(ptr)
	}).Export("free")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, a, b uint32) uint32 {
		return uint32(int32(h.fnStrcmp(a, b)))
	}).Export("strcmp")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, s uint32) uint32 {
		return h.fnPuts(s)
	}).Export("puts")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, format, args uint32) uint32 {
		return h.fnIprintf(format, args)
	}).Export("iprintf")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, s, c uint32) uint32 {
		return h.fnStrchr(s, byte(c))
	}).Export("strchr")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, stream, format, args uint32) uint32 {
		return h.fnIprintf(format, args)
	}).Export("fiprintf")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, size, count, stream uint32) uint32 {
		return size * count
	}).Export("fwrite")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, v uint32) uint32 {
		return uint32(strings.ToLower(string(rune(v)))[0])
	}).Export("tolower")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, dst, src, n uint32) uint32 {
		return h.fnStrncat(dst, src, n)
	}).Export("strncat")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, haystack, needle uint32) uint32 {
		return h.fnStrstr(haystack, needle)
	}).Export("strstr")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, s uint32) uint32 {
		return uint32(h.fnAtoi(s))
	}).Export("atoi")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, ptr, c, n uint32) uint32 {
		return h.fnMemchr(ptr, byte(c), n)
	}).Export("memchr")
	builder.NewFunctionBuilder().WithFunc(func(ctx context.Context, m api.Module, s, c uint32) uint32 {
		return h.fnStrrchr(s, byte(c))
	}).Export("strrchr")

	_, err := builder.Instantiate(ctx)
	return err
}

func alignUp(v, align uint32) uint32 {
	return (v + align - 1) &^ (align - 1)
}

func (h *hostState) alloc(size uint32) (uint32, error) {
	if size == 0 {
		size = 1
	}
	size = alignUp(size, 8)

	h.mu.Lock()
	defer h.mu.Unlock()

	for i, block := range h.freeList {
		if block.size < size {
			continue
		}
		ptr := block.ptr
		if block.size == size {
			h.freeList = append(h.freeList[:i], h.freeList[i+1:]...)
		} else {
			h.freeList[i].ptr += size
			h.freeList[i].size -= size
		}
		h.allocs[ptr] = size
		return ptr, nil
	}

	if h.next+size > h.heapLimit {
		return 0, fmt.Errorf("capstone wasm heap exhausted allocating %d bytes", size)
	}
	ptr := h.next
	h.next += size
	h.allocs[ptr] = size
	return ptr, nil
}

func (h *hostState) free(ptr uint32) {
	if ptr == 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	size, ok := h.allocs[ptr]
	if !ok {
		return
	}
	delete(h.allocs, ptr)
	h.freeList = append(h.freeList, memoryBlock{ptr: ptr, size: size})
}

func (h *hostState) allocBytes(data []byte) (uint32, error) {
	ptr, err := h.alloc(uint32(len(data)))
	if err != nil {
		return 0, err
	}
	if len(data) == 0 {
		return ptr, nil
	}
	if !h.memory.Write(ptr, data) {
		h.free(ptr)
		return 0, errors.New("write wasm buffer")
	}
	return ptr, nil
}

func (h *hostState) readCString(ptr uint32) (string, error) {
	if ptr == 0 {
		return "", nil
	}
	var out strings.Builder
	for {
		b, ok := h.memory.ReadByte(ptr)
		if !ok {
			return "", errors.New("read c string")
		}
		if b == 0 {
			return out.String(), nil
		}
		out.WriteByte(b)
		ptr++
	}
}

func (h *hostState) fnCalloc(count, size uint32) uint32 {
	total := count * size
	ptr, err := h.alloc(total)
	if err != nil {
		return 0
	}
	zero := make([]byte, int(total))
	if total > 0 && !h.memory.Write(ptr, zero) {
		h.free(ptr)
		return 0
	}
	return ptr
}

func (h *hostState) fnRealloc(ptr, size uint32) uint32 {
	if ptr == 0 {
		newPtr, _ := h.alloc(size)
		return newPtr
	}
	if size == 0 {
		h.free(ptr)
		return 0
	}

	h.mu.Lock()
	oldSize := h.allocs[ptr]
	h.mu.Unlock()
	if oldSize >= alignUp(size, 8) {
		return ptr
	}

	newPtr, err := h.alloc(size)
	if err != nil {
		return 0
	}
	buf, ok := h.memory.Read(ptr, oldSize)
	if !ok || !h.memory.Write(newPtr, buf) {
		h.free(newPtr)
		return 0
	}
	h.free(ptr)
	return newPtr
}

func (h *hostState) fnStrlen(ptr uint32) uint32 {
	var n uint32
	for {
		b, ok := h.memory.ReadByte(ptr + n)
		if !ok || b == 0 {
			return n
		}
		n++
	}
}

func (h *hostState) fnStrncpy(dst, src, n uint32) uint32 {
	for i := uint32(0); i < n; i++ {
		b, ok := h.memory.ReadByte(src + i)
		if !ok {
			return dst
		}
		_ = h.memory.WriteByte(dst+i, b)
		if b == 0 {
			for j := i + 1; j < n; j++ {
				_ = h.memory.WriteByte(dst+j, 0)
			}
			return dst
		}
	}
	return dst
}

func (h *hostState) fnStrcmp(a, b uint32) int32 {
	for {
		ab, _ := h.memory.ReadByte(a)
		bb, _ := h.memory.ReadByte(b)
		if ab != bb {
			return int32(ab) - int32(bb)
		}
		if ab == 0 {
			return 0
		}
		a++
		b++
	}
}

func (h *hostState) fnPuts(s uint32) uint32 {
	str, _ := h.readCString(s)
	return uint32(len(str) + 1)
}

func (h *hostState) fnIprintf(format, args uint32) uint32 {
	formatted, _ := h.formatFromVA(format, args)
	return uint32(len(formatted))
}

func (h *hostState) fnStrchr(s uint32, c byte) uint32 {
	for {
		b, ok := h.memory.ReadByte(s)
		if !ok {
			return 0
		}
		if b == c {
			return s
		}
		if b == 0 {
			return 0
		}
		s++
	}
}

func (h *hostState) fnStrrchr(s uint32, c byte) uint32 {
	var last uint32
	for {
		b, ok := h.memory.ReadByte(s)
		if !ok {
			return last
		}
		if b == c {
			last = s
		}
		if b == 0 {
			return last
		}
		s++
	}
}

func (h *hostState) fnStrncat(dst, src, n uint32) uint32 {
	base := dst + h.fnStrlen(dst)
	for i := uint32(0); i < n; i++ {
		b, ok := h.memory.ReadByte(src + i)
		if !ok {
			break
		}
		if b == 0 {
			_ = h.memory.WriteByte(base+i, 0)
			return dst
		}
		_ = h.memory.WriteByte(base+i, b)
	}
	_ = h.memory.WriteByte(base+n, 0)
	return dst
}

func (h *hostState) fnStrstr(haystack, needle uint32) uint32 {
	hay, _ := h.readCString(haystack)
	nee, _ := h.readCString(needle)
	idx := strings.Index(hay, nee)
	if idx < 0 {
		return 0
	}
	return haystack + uint32(idx)
}

func (h *hostState) fnAtoi(ptr uint32) int32 {
	s, _ := h.readCString(ptr)
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 32)
	return int32(v)
}

func (h *hostState) fnMemchr(ptr uint32, c byte, n uint32) uint32 {
	buf, ok := h.memory.Read(ptr, n)
	if !ok {
		return 0
	}
	for i, b := range buf {
		if b == c {
			return ptr + uint32(i)
		}
	}
	return 0
}

func (h *hostState) fnSnprintf(dst, size, formatPtr, argsPtr uint32) uint32 {
	formatted, _ := h.formatFromVA(formatPtr, argsPtr)
	return h.writeSnprintf(dst, size, formatted)
}

func (h *hostState) writeSnprintf(dst, size uint32, formatted string) uint32 {
	fullLen := uint32(len(formatted))
	if size == 0 {
		return fullLen
	}
	limit := int(size) - 1
	if limit < 0 {
		limit = 0
	}
	if len(formatted) > limit {
		formatted = formatted[:limit]
	}
	_ = h.memory.WriteString(dst, formatted)
	_ = h.memory.WriteByte(dst+uint32(len(formatted)), 0)
	return fullLen
}

type vaReader struct {
	memory api.Memory
	ptr    uint32
}

func (r *vaReader) nextI32() uint32 {
	r.ptr = alignUp(r.ptr, 4)
	v, _ := r.memory.ReadUint32Le(r.ptr)
	r.ptr += 4
	return v
}

func (r *vaReader) nextI64() uint64 {
	r.ptr = alignUp(r.ptr, 8)
	v, _ := r.memory.ReadUint64Le(r.ptr)
	r.ptr += 8
	return v
}

func (r *vaReader) nextF64() float64 {
	return math.Float64frombits(r.nextI64())
}

func (h *hostState) formatFromVA(formatPtr, argsPtr uint32) (string, error) {
	format, err := h.readCString(formatPtr)
	if err != nil {
		return "", err
	}
	reader := &vaReader{memory: h.memory, ptr: argsPtr}

	var out strings.Builder
	for i := 0; i < len(format); i++ {
		if format[i] != '%' {
			out.WriteByte(format[i])
			continue
		}
		if i+1 < len(format) && format[i+1] == '%' {
			out.WriteByte('%')
			i++
			continue
		}

		spec, consumed := parseFormatSpec(format[i+1:])
		i += consumed

		var rendered string
		switch spec.verb {
		case 's':
			ptr := reader.nextI32()
			s, _ := h.readCString(ptr)
			rendered = s
		case 'c':
			rendered = string(rune(reader.nextI32()))
		case 'd', 'i':
			if spec.length == "ll" {
				rendered = strconv.FormatInt(int64(reader.nextI64()), 10)
			} else {
				rendered = strconv.FormatInt(int64(int32(reader.nextI32())), 10)
			}
		case 'u':
			if spec.length == "ll" {
				rendered = strconv.FormatUint(reader.nextI64(), 10)
			} else {
				rendered = strconv.FormatUint(uint64(reader.nextI32()), 10)
			}
		case 'x', 'X':
			var v uint64
			if spec.length == "ll" {
				v = reader.nextI64()
			} else {
				v = uint64(reader.nextI32())
			}
			rendered = strconv.FormatUint(v, 16)
			if spec.verb == 'X' {
				rendered = strings.ToUpper(rendered)
			}
		case 'p':
			rendered = fmt.Sprintf("0x%x", reader.nextI32())
		case 'f':
			rendered = strconv.FormatFloat(reader.nextF64(), 'f', -1, 64)
		case 'e':
			rendered = strconv.FormatFloat(reader.nextF64(), 'e', -1, 64)
		default:
			rendered = "%" + spec.raw
		}

		if spec.width > 0 && len(rendered) < spec.width {
			pad := strings.Repeat(string(spec.padByte()), spec.width-len(rendered))
			if spec.left {
				rendered += pad
			} else {
				rendered = pad + rendered
			}
		}
		out.WriteString(rendered)
	}
	return out.String(), nil
}

type formatSpec struct {
	raw    string
	width  int
	left   bool
	zero   bool
	length string
	verb   byte
}

func (s formatSpec) padByte() byte {
	if s.zero && !s.left {
		return '0'
	}
	return ' '
}

func parseFormatSpec(input string) (formatSpec, int) {
	spec := formatSpec{}
	i := 0
	for i < len(input) {
		switch input[i] {
		case '-', '+', ' ', '#':
			if input[i] == '-' {
				spec.left = true
			}
			i++
		case '0':
			spec.zero = true
			i++
		default:
			goto width
		}
	}

width:
	for i < len(input) && input[i] >= '0' && input[i] <= '9' {
		spec.width = spec.width*10 + int(input[i]-'0')
		i++
	}
	if i < len(input) && input[i] == '.' {
		i++
		for i < len(input) && input[i] >= '0' && input[i] <= '9' {
			i++
		}
	}
	if i+1 < len(input) && input[i] == 'l' && input[i+1] == 'l' {
		spec.length = "ll"
		i += 2
	} else if i < len(input) && (input[i] == 'l' || input[i] == 'h') {
		spec.length = string(input[i])
		if i+1 < len(input) && input[i+1] == input[i] {
			spec.length += string(input[i])
			i++
		}
		i++
	}
	if i < len(input) {
		spec.verb = input[i]
		i++
	}
	spec.raw = input[:i]
	return spec, i
}
