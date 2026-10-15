package core

import (
	"errors"
	"strings"

	qrcode "github.com/skip2/go-qrcode"
)

// maxTerminalQRWidth is the approximate max QR bitmap width (modules incl. quiet zone) before we switch to Braille packing.
const maxTerminalQRWidth = 76

// formatMFAQRForTerminal renders the otpauth URL as Unicode graphics for SSH clients (UTF-8).
// Uses half-block characters (▀▄█) when narrow enough; otherwise Braille (2×4 modules per cell) to avoid line wrap.
func formatMFAQRForTerminal(otpauth string) (string, error) {
	qr, err := qrcode.New(otpauth, qrcode.Low)
	if err != nil {
		return "", err
	}
	bmp := qr.Bitmap()
	if len(bmp) == 0 || len(bmp[0]) == 0 {
		return "", errors.New("empty qr bitmap")
	}
	var s string
	if len(bmp[0]) > maxTerminalQRWidth {
		s = qrBitmapToBraille(bmp)
	} else {
		s = strings.ReplaceAll(qr.ToSmallString(false), "\n", "\r\n")
	}
	if !strings.HasSuffix(s, "\r\n") {
		s += "\r\n"
	}
	return s, nil
}

func brailleFrom4x2(block [4][2]bool) rune {
	var b byte
	if block[0][0] {
		b |= 1 << 0 // dot 1
	}
	if block[1][0] {
		b |= 1 << 1 // dot 2
	}
	if block[2][0] {
		b |= 1 << 2 // dot 3
	}
	if block[0][1] {
		b |= 1 << 3 // dot 4
	}
	if block[1][1] {
		b |= 1 << 4 // dot 5
	}
	if block[2][1] {
		b |= 1 << 5 // dot 6
	}
	if block[3][0] {
		b |= 1 << 6 // dot 7
	}
	if block[3][1] {
		b |= 1 << 7 // dot 8
	}
	return rune(0x2800 + uint16(b))
}

func qrBitmapToBraille(bits [][]bool) string {
	h, w := len(bits), len(bits[0])
	// Work on a copy; padding must not mutate the library's bitmap.
	clone := make([][]bool, h)
	for y := 0; y < h; y++ {
		clone[y] = make([]bool, w)
		copy(clone[y], bits[y])
	}
	bits = clone
	// Pad to multiples of 4 (height) and 2 (width)
	for h%4 != 0 {
		bits = append(bits, make([]bool, w))
		h++
	}
	for w%2 != 0 {
		for y := 0; y < h; y++ {
			bits[y] = append(bits[y], false)
		}
		w++
	}
	var sb strings.Builder
	for y := 0; y < h; y += 4 {
		for x := 0; x < w; x += 2 {
			var blk [4][2]bool
			for dy := 0; dy < 4; dy++ {
				for dx := 0; dx < 2; dx++ {
					blk[dy][dx] = bits[y+dy][x+dx]
				}
			}
			sb.WriteRune(brailleFrom4x2(blk))
		}
		sb.WriteString("\r\n")
	}
	return sb.String()
}
