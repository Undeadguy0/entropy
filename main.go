package main

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/cobra"
)

const (
	LOWERCASE = "abcdefghijklmnopqrstuvwxyz"
	UPPERCASE = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	DIGITS    = "0123456789"
	SPECIALS  = "!@#$%^&*-_+="

	DEFAULT_LENGTH = 32
)

type Encoding int

const (
	EncNone Encoding = iota
	EncHex
	EncBase32
	EncBase64
	EncBase62
)

var encodingNames = map[string]Encoding{
	"hex":    EncHex,
	"base32": EncBase32,
	"base64": EncBase64,
	"base62": EncBase62,
}

type Config struct {
	Length      int
	Count       int
	UseLower    bool
	UseUpper    bool
	UseDigits   bool
	UseSpecials bool
	UseAll      bool
	Prefix      string
	Suffix      string
	OutputFile  string
	Overwrite   bool
	Encoding    Encoding
}

func main() {
	cfg := &Config{}

	rootCmd := &cobra.Command{
		Use:  "entropy",
		Long: "Cryptographically secure password generator with multiple output encodings",
		RunE: func(cmd *cobra.Command, args []string) error {
			return run(cfg)
		},
	}

	rootCmd.Flags().IntVarP(&cfg.Length, "len", "l", DEFAULT_LENGTH, "Password length in characters")
	rootCmd.Flags().IntVarP(&cfg.Count, "repeat", "r", 1, "Number of passwords to generate")
	rootCmd.Flags().BoolVarP(&cfg.UseLower, "lowercase", "L", false, "Use lowercase letters")
	rootCmd.Flags().BoolVarP(&cfg.UseUpper, "uppercase", "U", false, "Use uppercase letters")
	rootCmd.Flags().BoolVarP(&cfg.UseDigits, "nums", "N", false, "Use digits")
	rootCmd.Flags().BoolVarP(&cfg.UseSpecials, "specials", "S", false, "Use special characters")
	rootCmd.Flags().BoolVarP(&cfg.UseAll, "all", "A", false, "Use all character sets above")
	rootCmd.Flags().StringVarP(&cfg.OutputFile, "write-to", "w", "", "Output file path (default: stdout)")
	rootCmd.Flags().BoolVarP(&cfg.Overwrite, "overwrite", "o", false, "Overwrite output file if exists")
	rootCmd.Flags().StringVar(&cfg.Prefix, "prefix", "", "Prefix for each password (not counted in length)")
	rootCmd.Flags().StringVar(&cfg.Suffix, "suffix", "", "Suffix for each password (not counted in length)")

	encStr := ""
	rootCmd.Flags().StringVar(&encStr, "encoding", "", "Output encoding: hex, base32, base64, base62")
	rootCmd.MarkFlagsMutuallyExclusive("encoding")

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}

	// Валидация encoding после парсинга флагов
	if encStr != "" {
		enc, ok := encodingNames[strings.ToLower(encStr)]
		if !ok {
			fmt.Fprintf(os.Stderr, "Error: unknown encoding %q (valid: hex, base32, base64, base62)\n", encStr)
			os.Exit(1)
		}
		cfg.Encoding = enc
	}
}

func run(cfg *Config) error {
	if err := validate(cfg); err != nil {
		return err
	}

	writer, err := resolveOutput(cfg.OutputFile, cfg.Overwrite)
	if err != nil {
		return err
	}
	defer func() {
		if f, ok := writer.(*os.File); ok {
			f.Close()
		}
	}()

	alphabet := buildAlphabet(cfg)
	if len(alphabet) == 0 {
		return errors.New("no character sets enabled (use -L, -U, -N, -S or -A)")
	}

	alphabetBytes := []byte(alphabet)
	alphabetSize := big.NewInt(int64(len(alphabetBytes)))

	var wg sync.WaitGroup
	errCh := make(chan error, cfg.Count)
	for i := 0; i < cfg.Count; i++ {
		wg.Go(func() {
			pwd := generatePassword(alphabetBytes, alphabetSize, cfg.Length)
			encoded := encodePassword(pwd, cfg.Encoding)
			line := cfg.Prefix + encoded + cfg.Suffix + "\n"
			if _, err := writer.Write([]byte(line)); err != nil {
				errCh <- err
			}
		})
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

func validate(cfg *Config) error {
	if cfg.Length < 1 {
		return errors.New("password length must be >= 1")
	}
	if cfg.Count < 1 {
		return errors.New("count must be >= 1")
	}
	if cfg.Overwrite && cfg.OutputFile == "" {
		return errors.New("overwrite flag requires --write-to")
	}
	return nil
}

func resolveOutput(path string, overwrite bool) (io.Writer, error) {
	if path == "" {
		return os.Stdout, nil
	}

	path = filepath.Clean(path)

	if !filepath.IsAbs(path) {
		wd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("get working dir: %w", err)
		}
		path = filepath.Join(wd, path)
	}

	parent := filepath.Dir(path)
	if _, err := os.Stat(parent); err != nil {
		return nil, fmt.Errorf("parent directory %s does not exist", parent)
	}

	if _, err := os.Stat(path); err == nil && !overwrite {
		return nil, fmt.Errorf("file %s exists and overwrite is disabled", path)
	}

	f, err := os.Create(path)
	if err != nil {
		return nil, fmt.Errorf("create file %s: %w", path, err)
	}
	return f, nil
}

func buildAlphabet(cfg *Config) string {
	var b strings.Builder
	if cfg.UseAll {
		b.WriteString(LOWERCASE)
		b.WriteString(UPPERCASE)
		b.WriteString(DIGITS)
		b.WriteString(SPECIALS)
	} else {
		if cfg.UseLower {
			b.WriteString(LOWERCASE)
		}
		if cfg.UseUpper {
			b.WriteString(UPPERCASE)
		}
		if cfg.UseDigits {
			b.WriteString(DIGITS)
		}
		if cfg.UseSpecials {
			b.WriteString(SPECIALS)
		}
	}
	return b.String()
}

// generatePassword возвращает []byte длины length из алфавита alphabetBytes
func generatePassword(alphabet []byte, alphabetSize *big.Int, length int) []byte {
	result := make([]byte, length)
	for i := range length {
		idx, _ := rand.Int(rand.Reader, alphabetSize)
		result[i] = alphabet[idx.Int64()]
	}
	return result
}

// encodePassword кодирует сгенерированные байты в выбранный формат
func encodePassword(data []byte, enc Encoding) string {
	switch enc {
	case EncHex:
		return hex.EncodeToString(data)
	case EncBase32:
		// RFC4648, без padding (RawStdEncoding)
		return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(data)
	case EncBase64:
		return base64.StdEncoding.EncodeToString(data)
	case EncBase62:
		return encodeBase62(data)
	default:
		return string(data)
	}
}

const base62Alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

func encodeBase62(data []byte) string {
	// Интерпретируем байты как большое число (little-endian для простоты)
	// и переводим в основание 62.
	n := new(big.Int).SetBytes(data)
	base := big.NewInt(62)
	zero := big.NewInt(0)

	if n.Cmp(zero) == 0 {
		return "0"
	}

	var result strings.Builder
	for n.Cmp(zero) > 0 {
		mod := new(big.Int)
		n.DivMod(n, base, mod)
		result.WriteByte(base62Alphabet[mod.Int64()])
	}
	// Разряды получены в обратном порядке
	runes := []rune(result.String())
	for i, j := 0, len(runes)-1; i < j; i, j = i+1, j-1 {
		runes[i], runes[j] = runes[j], runes[i]
	}
	return string(runes)
}
