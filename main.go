package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"strings"
	"unsafe"

	"github.com/DQNEO/goas/goas"
)

var oFlag = flag.String("o", "a.out", "output file")

var debug = flag.Bool("d", false, "show debug message")

func debugf(s string, a ...interface{}) {
	if !*debug {
		return
	}
	fmt.Fprintf(os.Stderr, s, a...)
}

func sortSectionsForBody(hasRelaText, hasRelaData, hasSymbols bool) []*section {
	var ss sections = make([]*section, 0, 8)
	ss.add(s_text)
	ss.add(s_data)
	ss.add(s_bss)

	if hasSymbols {
		ss.add(s_symtab)
		ss.add(s_strtab)
	}

	if hasRelaText {
		ss.add(s_rela_text)
	}

	if hasRelaData {
		ss.add(s_rela_data)
	}

	ss.add(s_shstrtab)
	return ss
}

type sections []*section

func (ss *sections) add(s *section) {
	*ss = append(*ss, s)
}

type section struct {
	name       string
	index      uint16
	header     *goas.Elf64_Shdr
	numZeroPad uintptr
	zeros      []uint8
	contents   []uint8
}

func buildSectionHeaders(hasRelaText, hasRelaData, hasSymbols bool) []*section {
	var ss sections = make([]*section, 0, 8)
	ss.add(&section{header: &goas.Elf64_Shdr{}}) // NULL section
	ss.add(s_text)
	if hasRelaText {
		ss.add(s_rela_text)
	}

	ss.add(s_data)

	if hasRelaData {
		ss.add(s_rela_data)
	}
	ss.add(s_bss)

	if hasSymbols {
		ss.add(s_symtab)
		ss.add(s_strtab)
	}
	ss.add(s_shstrtab)

	for i, s := range ss {
		s.index = uint16(i)
	}

	return ss
}

var s_text = &section{
	name: ".text",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_PROGBITS,
		Sh_flags:     0x06, // SHF_ALLOC|SHF_EXECINSTR
		Sh_addr:      0,
		Sh_link:      0,
		Sh_info:      0,
		Sh_addralign: 0x01,
		Sh_entsize:   0,
	},
}

var s_rela_text = &section{
	name: ".rela.text",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_RELA,
		Sh_flags:     0x40, // * ??
		Sh_link:      0x00, // The section header index of the associated symbol table
		Sh_info:      0x01,
		Sh_addralign: 0x08,
		Sh_entsize:   0x18,
	},
}

var s_rela_data = &section{
	name: ".rela.data",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_RELA,
		Sh_flags:     0x40, // I ??
		Sh_info:      0x02, // section idx of .data
		Sh_addralign: 0x08,
		Sh_entsize:   0x18,
	},
}

var s_data = &section{
	name: ".data",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_PROGBITS,
		Sh_flags:     0x03, // SHF_WRITE|SHF_ALLOC
		Sh_addr:      0,
		Sh_link:      0,
		Sh_info:      0,
		Sh_addralign: 0x01,
		Sh_entsize:   0,
	},
}

var s_bss = &section{
	name: ".bss",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_NOBITS,
		Sh_flags:     0x03, // SHF_WRITE|SHF_ALLOC
		Sh_addr:      0,
		Sh_link:      0,
		Sh_info:      0,
		Sh_addralign: 0x01,
		Sh_entsize:   0,
	},
}

//  ".symtab"
//  SHT_SYMTAB (symbol table)
var s_symtab = &section{
	name: ".symtab",
	header: &goas.Elf64_Shdr{
		Sh_type:  goas.SHT_SYMTAB, // SHT_SYMTAB
		Sh_flags: 0,
		Sh_addr:  0,
		//	Sh_link:      0x05, // section index of .strtab ?
		Sh_addralign: 0x08,
		Sh_entsize:   0x18,
	},
}

var s_shstrtab = &section{
	name: ".shstrtab",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_STRTAB,
		Sh_flags:     0,
		Sh_addr:      0,
		Sh_link:      0,
		Sh_info:      0,
		Sh_addralign: 0x01,
		Sh_entsize:   0,
	},
}

// ".strtab"
//
// This section holds strings, most commonly the strings that
//              represent the names associated with symbol table entries.
//              If the file has a loadable segment that includes the
//              symbol string table, the section's attributes will include
//              the SHF_ALLOC bit.  Otherwise, the bit will be off.
// This section is of type SHT_STRTAB.
var s_strtab = &section{
	name: ".strtab",
	header: &goas.Elf64_Shdr{
		Sh_type:      goas.SHT_STRTAB,
		Sh_flags:     0,
		Sh_addr:      0,
		Sh_link:      0,
		Sh_info:      0,
		Sh_addralign: 0x01,
		Sh_entsize:   0,
	},
}

func calcOffsetOfSection(s *section, prev *section) {
	tentative_offset := prev.header.Sh_offset + prev.header.Sh_size
	var align = s.header.Sh_addralign
	if align == 0 || align == 1 {
		s.numZeroPad = 0
	} else {
		mod := tentative_offset % align
		if mod == 0 {
			s.numZeroPad = 0
		} else {
			s.numZeroPad = align - mod
		}
	}
	s.header.Sh_offset = tentative_offset + s.numZeroPad
	s.header.Sh_size = uintptr(len(s.contents))
}

func makeStrTab(symbols []string) []byte {
	var nameOffset uint32
	var data []byte = []byte{0x00}
	nameOffset++
	for _, sym := range symbols {
		//sym.nameOffset = nameOffset
		buf := append([]byte(sym), 0x00)
		data = append(data, buf...)
		nameOffset += uint32(len(buf))
	}

	return data
}

func makeSectionNames(hasRelaText, hasRelaData, hasSymbols bool) []string {
	var r []string

	if hasSymbols {
		r = append(r, ".symtab", ".strtab")
	}

	var dataName string
	var textName string

	if hasRelaData {
		dataName = ".rela.data"
	} else {
		dataName = ".data"
	}

	if hasRelaText {
		textName = ".rela.text"
	} else {
		textName = ".text"
	}

	r = append(r, ".shstrtab", textName, dataName, ".bss")
	return r
}

// Make contents of .shstrtab"
func makeShStrTab(sectionNames []string) []byte {
	buf := []byte{0x00}
	for _, name := range sectionNames {
		buf = append(buf, name...)
		buf = append(buf, 0)
	}
	return buf
}

func resolveShNames(shstrtab_contents []byte, ss []*section) {
	for _, s := range ss {
		idx := bytes.Index(shstrtab_contents, []byte(s.name))
		if idx <= 0 {
			panic(s.name + " is not found in .strtab contents")
		}
		s.header.Sh_name = uint32(idx)
	}
}

const STT_SECTION = 0x03

func isDataSymbolUsed(definedSymbols map[string]*goas.SymbolDefinition, relaTextUsers []*goas.RelaTextUser, relaDataUsers []*goas.RelaDataUser) bool {
	for _, rel := range relaTextUsers {
		symdef, ok := definedSymbols[rel.Uses]
		if ok {
			if symdef.Section == ".data" {
				return true
			}
		}
	}

	for _, rel := range relaDataUsers {
		symdef, ok := definedSymbols[rel.Uses]
		if ok {
			if symdef.Section == ".data" {
				return true
			}
		}
	}
	return false
}

func buildSymbolTable(addData bool, globalSymbols map[string]bool, symbolsInLexicalOrder []string) (uint32, []uint8, map[string]int) {
	var symbolIndex = make(map[string]int)

	var symbolTable = []*goas.Elf64_Sym{
		&goas.Elf64_Sym{}, // NULL entry
	}

	if addData {
		symbolIndex[".data"] = len(symbolTable)
		symbolTable = append(symbolTable, &goas.Elf64_Sym{
			St_name:  0,
			St_info:  STT_SECTION,
			St_other: 0,
			St_shndx: uint16(s_data.index),
			St_value: 0,
			St_size:  0,
		})
	}

	var localSymbols []string
	var globalDefinedSymbols []string
	var globalUndefinedSymbols []string
	for _, sym := range symbolsInLexicalOrder {
		if strings.HasPrefix(sym, ".L") {
			// https://sourceware.org/binutils/docs-2.37/as.html#Symbol-Names
			// Local Symbol Names
			// A local symbol is any symbol beginning with certain local label prefixes. By default, the local label prefix is ‘.L’ for ELF systems or ‘L’ for traditional a.out systems, but each target may have its own set of local label prefixes. On the HPPA local symbols begin with ‘L$’.
			//
			// Local symbols are defined and used within the assembler, but they are normally not saved in object files. Thus, they are not visible when debugging. You may use the ‘-L’ option (see Include Local Symbols) to retain the local symbols in the object files.
			continue
		}
		isGlobal := globalSymbols[sym]
		_, isDefined := goas.DefinedSymbols[sym]
		if !isDefined {
			isGlobal = true
		}

		if !isGlobal {
			localSymbols = append(localSymbols, sym)
		} else {
			if isDefined {
				globalDefinedSymbols = append(globalDefinedSymbols, sym)
			} else {
				globalUndefinedSymbols = append(globalUndefinedSymbols, sym)
			}
		}
	}

	// local => global defined => global undefined
	allSymbolsForElf := append(localSymbols, globalDefinedSymbols...)
	allSymbolsForElf = append(allSymbolsForElf, globalUndefinedSymbols...)

	s_strtab.contents = makeStrTab(allSymbolsForElf)

	// https://reviews.llvm.org/D28950
	// The sh_info field of the SHT_SYMTAB section holds the index for the first non-local symbol.
	var indexOfFirstNonLocalSymbol int

	for _, symname := range allSymbolsForElf {
		isGlobal := globalSymbols[symname]
		sym, isDefined := goas.DefinedSymbols[symname]
		var addr uintptr
		var shndx uint16
		if isDefined {
			switch sym.Section {
			case ".text":
				shndx = s_text.index
				addr = sym.Instr.Addr
			case ".data":
				shndx = s_data.index
				addr = sym.Address
			default:
				panic("TBI")
			}
		} else {
			isGlobal = true
		}

		name_offset := bytes.Index(s_strtab.contents, append([]byte(symname), 0x0))
		if name_offset < 0 {
			panic("name_offset should not be negative")
		}
		var st_info uint8
		if isGlobal {
			st_info = 0x10 // GLOBAL ?
		}
		e := &goas.Elf64_Sym{
			St_name:  uint32(name_offset),
			St_info:  st_info,
			St_other: 0,
			St_shndx: shndx,
			St_value: addr,
		}
		index := len(symbolTable)
		symbolTable = append(symbolTable, e)

		symbolIndex[symname] = index
		if isGlobal {
			if indexOfFirstNonLocalSymbol == 0 {
				indexOfFirstNonLocalSymbol = index
			}
		}
	}

	var sh_info uint32
	// I don't know why we need this. Just Follow GNU.
	if indexOfFirstNonLocalSymbol == 0 {
		sh_info = uint32(len(symbolTable))
	} else {
		sh_info = uint32(indexOfFirstNonLocalSymbol)
	}

	var contents []uint8
	for _, entry := range symbolTable {
		buf := ((*[unsafe.Sizeof(goas.Elf64_Sym{})]byte)(unsafe.Pointer(entry)))[:]
		contents = append(contents, buf...)
	}

	return sh_info, contents, symbolIndex
}

var first *goas.Instruction

func resolveVariableLengthInstrs(instrs []*goas.Instruction) []*goas.Instruction {
	var todos []*goas.Instruction
	for _, vr := range instrs {
		sym, ok := goas.DefinedSymbols[vr.Varcode.TrgtSymbol]
		if !ok {
			continue
		}
		diff, min, max, isLenDecided := goas.CalcDistance(vr, sym)
		if isLenDecided {
			if goas.IsInInt8Range(diff) {
				// rel8
				vr.Code = vr.Varcode.Rel8Code
				vr.Code[vr.Varcode.Rel8Offset] = uint8(diff)
			} else {
				// rel32
				diffInt32 := int32(diff)
				var buf *[4]byte = (*[4]byte)(unsafe.Pointer(&diffInt32))
				code, offset := vr.Varcode.Rel32Code, vr.Varcode.Rel32Offset
				code[offset] = buf[0]
				code[offset+1] = buf[1]
				code[offset+2] = buf[2]
				code[offset+3] = buf[3]
				vr.Code = code
			}
			vr.IsLenDecided = true
		} else {
			if goas.IsInInt8Range(max) {
				vr.IsLenDecided = true
				vr.Varcode.Rel32Code = nil
				vr.Code = vr.Varcode.Rel8Code
			} else if !goas.IsInInt8Range(min) {
				vr.IsLenDecided = true
				vr.Varcode.Rel8Code = nil
				vr.Code = vr.Varcode.Rel32Code
			}
			todos = append(todos, vr)
		}
	}

	return todos
}

func encodeAllText(ss []*goas.Stmt) []byte {
	var insts []*goas.Instruction
	var index int
	var prev *goas.Instruction
	for _, s := range ss {
		if s.LabelSymbol == "" && s.KeySymbol == "" {
			continue
		}
		instr := goas.Encode(s)
		if s.LabelSymbol != "" {
			goas.DefinedSymbols[s.LabelSymbol].Instr = instr
		}
		insts = append(insts, instr)
		instr.Index = index
		index++
		if first == nil {
			first = instr
		} else {
			prev.Next = instr
		}
		prev = instr
	}

	// Optimize instructions length
	for len(goas.VariableInstrs) > 0 {
		goas.VariableInstrs = resolveVariableLengthInstrs(goas.VariableInstrs)
	}

	var allText []byte
	var textAddr uintptr
	for instr := first; instr != nil; instr = instr.Next {
		instr.Addr = textAddr
		allText = append(allText, instr.Code...)
		textAddr += uintptr(len(instr.Code))
	}

	// Resolve call targets
	for _, call := range goas.CallTargets {
		callee, ok := goas.DefinedSymbols[call.TrgtSymbol]
		if !ok {
			continue
		}
		diff := callee.Instr.Addr - call.Caller.Next.Addr
		placeToEmbed := call.Caller.Addr + call.Offset
		diffInt32 := int32(diff)
		var buf *[4]byte = (*[4]byte)(unsafe.Pointer(&diffInt32))
		allText[placeToEmbed] = buf[0]
		allText[placeToEmbed+1] = buf[1]
		allText[placeToEmbed+2] = buf[2]
		allText[placeToEmbed+3] = buf[3]
	}
	return allText
}

func encodeAllData(ss []*goas.Stmt) []byte {
	var dataAddr uintptr
	var allData []byte
	for _, s := range ss {
		buf := goas.EncodeData(s, dataAddr)
		dataAddr += uintptr(len(buf))
		allData = append(allData, buf...)
	}
	return allData
}

func main() {
	flag.Parse()

	var inFiles []string

	if flag.NArg() > 0 {
		inFiles = flag.Args()
	} else {
		inFiles = []string{"/dev/stdin"}
	}
	debugf("[main] input files are: %s\n", inFiles)
	outputFile := *oFlag
	debugf("[main] output file is: %s\n", outputFile)
	w, err := os.Create(outputFile)
	if err != nil {
		panic(err)
	}

	stmts, symbolsInLexicalOrder := goas.ParseFiles(inFiles)

	var textStmts []*goas.Stmt
	var dataStmts []*goas.Stmt

	var globalSymbols = make(map[string]bool)
	var currentSection = ".text"
	for _, s := range stmts {

		if s.LabelSymbol != "" {
			goas.DefinedSymbols[s.LabelSymbol] = &goas.SymbolDefinition{
				Name:    s.LabelSymbol,
				Section: currentSection,
			}
		}

		switch s.KeySymbol {
		case ".data":
			currentSection = ".data"
			continue
		case ".text":
			currentSection = ".text"
			continue
		case ".global":
			globalSymbols[s.Operands[0].(*goas.SymbolExpr).Name] = true
			continue
		}

		switch currentSection {
		case ".data":
			dataStmts = append(dataStmts, s)
		case ".text":
			textStmts = append(textStmts, s)
		}
	}

	s_text.contents = encodeAllText(textStmts)
	s_data.contents = encodeAllData(dataStmts)

	hasRelaText := len(goas.RelaTextUsers) > 0
	hasRelaData := len(goas.RelaDataUsers) > 0
	hasSymbols := len(goas.DefinedSymbols) > 0

	sectionHeaders := buildSectionHeaders(hasRelaText, hasRelaData, hasSymbols)

	if hasSymbols {
		s_symtab.header.Sh_link = uint32(s_strtab.index) // @TODO confirm the reason to do this

		if hasRelaText {
			s_rela_text.header.Sh_link = uint32(s_symtab.index)
		}

		if hasRelaData {
			s_rela_data.header.Sh_link = uint32(s_symtab.index)
			s_rela_data.header.Sh_info = uint32(s_data.index)
		}
	}

	var symbolIndex map[string]int

	if len(goas.DefinedSymbols) > 0 {
		dataSymbolUsed := isDataSymbolUsed(goas.DefinedSymbols, goas.RelaTextUsers, goas.RelaDataUsers)
		s_symtab.header.Sh_info, s_symtab.contents, symbolIndex = buildSymbolTable(dataSymbolUsed, globalSymbols, symbolsInLexicalOrder)
	}

	debugf("[main] building sections ...\n")
	sectionNames := makeSectionNames(hasRelaText, hasRelaData, hasSymbols)
	s_shstrtab.contents = makeShStrTab(sectionNames)
	resolveShNames(s_shstrtab.contents, sectionHeaders[1:])

	s_rela_text.contents = buildRelaTextBody(goas.RelaTextUsers, symbolIndex)
	s_rela_data.contents = buildRelaDataBody(goas.RelaDataUsers)

	sectionInBodyOrder := sortSectionsForBody(hasRelaText, hasRelaData, hasSymbols)
	goas.Assert(len(sectionInBodyOrder) == len(sectionHeaders)-1, "sections len unmatch")
	debugf("[main] writing ELF file ...\n")
	elfFile := prepareElfFile(sectionInBodyOrder, sectionHeaders)
	elfFile.WriteTo(w)
}

func buildRelaTextBody(relaTextUsers []*goas.RelaTextUser, symbolIndex map[string]int) []byte {
	var contents []byte

	for _, ru := range relaTextUsers {
		sym, defined := goas.DefinedSymbols[ru.Uses]
		var addr int64
		if defined {
			// skip symbols that belong to the same section
			if sym.Section == ".text" {
				continue
			}
			addr = int64(sym.Address)
		}

		var typ uint64
		if ru.ToJump {
			typ = goas.R_X86_64_PLT32
		} else {
			typ = goas.R_X86_64_PC32
		}

		var symIdx int
		if defined && sym.Section == ".data" {
			symIdx = symbolIndex[".data"]
		} else {
			symIdx = symbolIndex[ru.Uses]
		}

		rela := &goas.Elf64_Rela{
			R_offset: ru.Instr.Addr + ru.Offset,
			R_info:   uint64(symIdx)<<32 + typ,
			R_addend: addr + ru.Adjust - 4,
		}
		p := (*[unsafe.Sizeof(goas.Elf64_Rela{})]byte)(unsafe.Pointer(rela))[:]
		contents = append(contents, p...)
	}
	return contents
}

func buildRelaDataBody(relaDataUsers []*goas.RelaDataUser) []byte {
	var contents []byte
	for _, ru := range relaDataUsers {
		sym, ok := goas.DefinedSymbols[ru.Uses]
		if !ok {
			panic("label not found")
		}

		var addr uintptr
		if sym.Section == ".text" {
			addr = sym.Instr.Addr
		} else {
			addr = sym.Address
		}

		rela := &goas.Elf64_Rela{
			R_offset: ru.Addr,
			R_info:   0x0100000001,
			R_addend: int64(addr),
		}
		p := (*[unsafe.Sizeof(goas.Elf64_Rela{})]byte)(unsafe.Pointer(rela))[:]
		contents = append(contents, p...)
	}
	return contents
}

func determineSectionOffsets(sectionBodies []*section) {
	firstSection := sectionBodies[0]
	firstSection.header.Sh_offset = unsafe.Sizeof(goas.Elf64_Ehdr{})
	firstSection.header.Sh_size = uintptr(len(firstSection.contents))
	for i := 1; i < len(sectionBodies); i++ {
		calcOffsetOfSection(
			sectionBodies[i], sectionBodies[i-1])
	}
}

func calcEShoff(last *goas.Elf64_Shdr) (uintptr, uintptr) {

	endOfLastSection := last.Sh_offset + last.Sh_size

	var paddingBeforeSHT uintptr
	// align shoff so that e_shoff % 8 be zero. (This is not required actually. Just following gcc's practice)
	mod := endOfLastSection % 8
	if mod != 0 {
		paddingBeforeSHT = 8 - mod
	}
	eshoff := endOfLastSection + paddingBeforeSHT
	return paddingBeforeSHT, eshoff
}

// static data for ELF header.
// e_shoff, e_shnum, and e_shstrndx will be set later dynamically.
var elfHeader = &goas.Elf64_Ehdr{
	E_ident: [goas.EI_NIDENT]uint8{
		0x7f, 0x45, 0x4c, 0x46, // 0x7F followed by "ELF"(45 4c 46) in ASCII;
		0x02,                                     // EI_CLASS:2=64-bit
		0x01,                                     // EI_DATA:1=little endian
		0x01,                                     // EI_VERSION:1=the original and current version of ELF.
		0x00,                                     // EI_OSABI: 0=System V
		0x00,                                     // EI_ABIVERSION:
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // EI_PAD: always zero.
	},
	E_type:      1,    // ET_REL
	E_machine:   0x3e, // AMD x86-64
	E_version:   1,
	E_entry:     0,
	E_phoff:     0,
	E_flags:     0,
	E_ehsize:    uint16(unsafe.Sizeof(goas.Elf64_Ehdr{})), // 64
	E_phentsize: 0,
	E_phnum:     0,
	E_shentsize: uint16(unsafe.Sizeof(goas.Elf64_Shdr{})), // 64
}

func prepareElfFile(sectionBodies []*section, sectionHeaders []*section) *goas.ElfFile {

	// Calculates offset and zero padding
	determineSectionOffsets(sectionBodies)

	lastSectionHeader := sectionHeaders[len(sectionHeaders)-1].header
	paddingBeforeSHT, eshoff := calcEShoff(lastSectionHeader)

	elfHeader.E_shoff = eshoff
	elfHeader.E_shnum = uint16(len(sectionHeaders))
	elfHeader.E_shstrndx = s_shstrtab.index

	// adjust zero padding before each section
	var sbs []*goas.ElfSectionBodies
	for _, sect := range sectionBodies {
		// Some sections may not have any contents
		if sect.contents != nil {
			sc := &goas.ElfSectionBodies{
				Bodies: sect.contents,
			}
			if sect.numZeroPad > 0 {
				// pad zeros when required
				sc.Zeros = make([]uint8, sect.numZeroPad)
			}
			sbs = append(sbs, sc)
		}
	}

	var sht []*goas.Elf64_Shdr
	for _, s := range sectionHeaders {
		sht = append(sht, s.header)
	}

	return &goas.ElfFile{
		Header:         elfHeader,
		SectionBodies:  sbs,
		ZeroPadding:    make([]uint8, paddingBeforeSHT),
		SectionHeaders: sht,
	}
}
