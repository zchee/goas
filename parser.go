package main

import (
	"fmt"
	"github.com/DQNEO/babygo/lib/strconv"
	"os"
	"strings"
)


// https://sourceware.org/binutils/docs-2.37/as.html#Symbol-Names
// Symbol names begin with a letter or with one of ‘._’.
// Symbol names do not start with a digit.
//  An exception to this rule is made for Local Labels.
func isSymbolBeginning(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z') || ch == '.' || ch == '_'
}

// On most machines, you can also use $ in symbol names.
func isSymbolLetter(ch byte) bool{
	return isSymbolBeginning(ch) || '0' <= ch && ch <= '9' || ch == '$'
}

func peekCh() byte {
	if idx == len(source) {
		return 255
	}
	return source[idx]
}

// https://sourceware.org/binutils/docs-2.37/as.html#Whitespace
// Whitespace is one or more blanks or tabs, in any order.
// Whitespace is used to separate symbols, and to make programs neater for people to read.
// Unless within character constants (see Character Constants), any whitespace means the same as exactly one space.
func skipWhitespaces() {
	for idx < len(source) && source[idx] != '\n' {
		ch := source[idx]
		if ch == ' ' || ch == '\t' {
			idx++
			continue
		}
		return
	}
}

func skipLineComment() {
	for  {
		ch := source[idx]
		if ch == '\n' {
			return
		}
		idx++
	}
}

func readIndirection() (regi string) {
	idx++
	if source[idx] == '%' {
		regi = readRegi()
		assert(source[idx] == ')', "")
		idx++

	} else {
		parseFail("TBI")
	}
	return regi
}

func expect(ch byte) {
	if source[idx] != ch {
		panic(fmt.Sprintf("[parser] %c is expected, but got %c at line %d", ch, source[idx], lineno))
	}
	idx++
}

func isAlphabet(ch byte) bool {
	return ('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'Z')
}

func readRegi() string {
	expect('%')
	var buf []byte
	for {
		ch := source[idx]
		if isAlphabet(ch) {
			idx++
			buf = append(buf, ch)
		} else {
			return string(buf)
		}
	}
}

func readSymbol(first byte) string {
	expect(first)
	var buf []byte  = []byte{first}
	for {
		ch := source[idx]
		if isSymbolLetter(ch) {
			buf = append(buf, ch)
			idx++
		} else {
			return string(buf)
		}
	}
}

func readStringLiteral() string {
	expect('"')
	var buf []byte
	for {
		ch := peekCh()
		switch ch {
		case '\\':
			expect('\\')
			ch := peekCh()
			idx++
			buf = append(buf, ch)
			continue
		case '"':
			idx++
			return string(buf)
		default:
			idx++
			buf = append(buf, ch)
		}
	}
}

func parseArith() string {
	n := readNumber()
	ch := source[idx]
	switch ch {
	case '+','-','*','/':
		idx++
		n2 := readNumber()
		return n + string(ch) + n2
	default:
		return n
	}
}

func readNumber() string {
	first := source[idx]
	idx++
	var buf []byte  = []byte{first}
	for {
		ch := peekCh()
		if ('0' <= ch && ch <= '9') || ch == 'x' || ('a' <= ch && ch <= 'f') {
			buf = append(buf, ch)
			idx++
		} else {
			return string(buf)
		}
	}
}


func isDirective(symbol string) bool {
	return len(symbol) > 0 && symbol[0] == '.'
}

func parseOperand() *operand {
	skipWhitespaces()
	ch := source[idx]
	assert(ch != '\n', "")

	switch {
	case isSymbolBeginning(ch):
		symbol := readSymbol(ch)
		if source[idx] == '(' {
			// indirection e.g. 24(%rbp)
			regi := readIndirection()
			return &operand{
				string: fmt.Sprintf("indirect %s(%s)", symbol, regi),
			}
		} else {
			// just a symbol
			return  &operand{
				string :string(symbol),
			}
		}
	case ch == '"':
		s := readStringLiteral()
		return  &operand{
			string :string("\"" + s + "\""),
		}
	case '0' <= ch && ch <= '9' || ch == '-': // "24", "-24(%rbp)"e
		n := parseArith()
		if source[idx] == '(' {
			// indirection e.g. 24(%rbp)
			regi := readIndirection()
			return &operand{
				string: fmt.Sprintf("indirect %s(%s)", n, regi),
			}
		} else {
			// just a number
			return  &operand{
				string :string(n),
			}
		}
	case ch == '(':
		regi := readIndirection()
		return &operand{
			string: fmt.Sprintf("indirect (%s)",  regi),
		}
	case ch == '$':
		idx++
		// "$123" "$-7"
		n := readNumber()
		return  &operand{
			string :string(n),
		}
	case ch == '%':
		regi := readRegi()
		return  &operand{
			string :string(regi),
		}
	default:
		parseFail("default:buf=" + string(source[idx:idx+4]))
	}
	return nil
}

func parseOperands(keySymbol string) []*operand {
	//if keySymbol[0] == '.' {
	//	// directive
	//} else {
	//	// instruction
	//}
	var operands []*operand
	for ; !atEOL();{
		op := parseOperand()
		operands = append(operands, op)
		skipWhitespaces()
		if source[idx] == ',' {
			idx++
			continue
		} else {
			break
		}
	}
	return operands
}

func trySymbol() string {
	first := source[idx]
	if isSymbolBeginning(first) {
		return readSymbol(first)
	} else {
		idx++
		return ""
	}
}

var source []byte
var idx int
var lineno int = 1

type operand struct {
	string
}

type statement struct {
	labelSymbol string
	keySymbol   string
	operands    []*operand
}

var emptyStatement = &statement{}

func atEOL() bool {
	return source[idx] == '\n' || source[idx] == '#'
}

func parseFail(msg string) {
	panic(msg + " at line " + strconv.Itoa(lineno))
}

func assert(bol bool, errorMsg string) {
	if !bol {
		parseFail("assert failed: " + errorMsg)
	}
}

func consumeEOL() {
	if source[idx] == '#' {
		skipLineComment()
	}
	if idx == len(source) {
		return
	}
	assert(source[idx] == '\n', "not newline, but got " + string(source[idx]))
	idx++
	lineno++
}

// https://sourceware.org/binutils/docs-2.37/as.html#Statements
//
// A statement ends at a newline character (‘\n’) or a line separator character.
// The newline or line separator character is considered to be part of the preceding statement.
// Newlines and separators within character constants are an exception: they do not end statements.
//
// It is an error to end any statement with end-of-file: the last character of any input file should be a newline.
//
// An empty statement is allowed, and may include whitespace. It is ignored.
//
// A statement begins with zero or more labels, optionally followed by a key symbol
// which determines what kind of statement it is.
// The key symbol determines the syntax of the rest of the statement.
// If the symbol begins with a dot ‘.’ then the statement is an assembler directive: typically valid for any computer. If the symbol begins with a letter the statement is an assembly language instruction: it assembles into a machine language instruction. Different versions of as for different computers recognize different instructions. In fact, the same symbol may represent a different instruction in a different computer’s assembly language.
//
// A label is a symbol immediately followed by a colon (:).
// Whitespace before a label or after a colon is permitted, but you may not have whitespace between a label’s symbol and its colon. See Labels.
func parseStmt() *statement {
	skipWhitespaces()
	if atEOL() {
		consumeEOL()
		return emptyStatement
	}
	var stmt = &statement{}
	symbol := trySymbol()
	//println("  got symbol " + symbol)
	//println("(a) next char is  " + string(source[idx]) + ".")
	if symbol == "" {
		assert(atEOL(), "not at EOL")
		consumeEOL()
		return emptyStatement
	}

	var keySymbol string

	if source[idx] == ':' {
		// this symbol is a label
		stmt.labelSymbol = symbol
		skipWhitespaces()
		if atEOL() {
			consumeEOL()
			return stmt
		}
		keySymbol = trySymbol()
		if len(keySymbol) == 0 {
			skipWhitespaces()
			assert(atEOL(), "not at EOL")
			consumeEOL()
			return stmt
		}
	} else {
		// this symbol is the key symbol in this statement
		keySymbol = symbol
	}
	stmt.keySymbol = keySymbol

	skipWhitespaces()
	//println("(b) next char is  " + string(source[idx]))
	if atEOL() {
		consumeEOL()
		return stmt
	}

	//println("  parsing operands...")
	operands := parseOperands(keySymbol)
	stmt.operands = operands
	consumeEOL()
	return stmt
}

// GAS Manual: https://sourceware.org/binutils/docs-2.37/as.html
func parse() []*statement {
	var stmts []*statement
	var i int = 1
	for idx < len(source) {
		//println(i, " reading...")
		s := parseStmt()
		stmts = append(stmts, s)
		i++
	}
	return stmts
}

func dumpStmt(i int, stmt *statement) {
	if stmt == emptyStatement {
		fmt.Printf("%03d| *\n", i)
	} else {
		var ops []string
		for _, o := range stmt.operands {
			ops = append(ops, o.string)
		}
		fmt.Printf("%04d|%29s: |%30s | %s\n", i, stmt.labelSymbol, stmt.keySymbol, strings.Join(ops, "  , "))
	}

}

func dumpStmts(stmts []*statement) {
	fmt.Printf("%4s|%29s: |%30s | %s\n", "Line", "Label", "Instruction", "Operands")
	for i, stmt := range stmts {
		if stmt == emptyStatement {
			continue
		}
		dumpStmt(i, stmt)
	}
}

type none bool

func debugParser() {
	var err error
	source, err = os.ReadFile("/dev/stdin")
	if err != nil {
		panic(err)
	}
	stmts := parse()


	dumpStmts(stmts)
	return

	insts := make(map[string]none)
	dircs := make(map[string]none)
	labels := make(map[string]none)

	for _, s := range stmts {
		if isDirective(s.keySymbol) {
			dircs[s.keySymbol] = true
		} else {
			insts[s.keySymbol] = true
		}
		labels[s.labelSymbol] = true
	}

	for k, _ := range labels {
		fmt.Printf("%v\n", k)
	}
	fmt.Println("------------------")
	for k, _ := range dircs {
		fmt.Printf("%v\n", k)
	}
	fmt.Println("------------------")
	for k, _ := range insts {
		fmt.Printf("%v\n", k)
	}
}
