package core

import _ "embed"

//go:embed web/index.html
var embeddedIndexHTML []byte

//go:embed web/style.css
var embeddedStyleCSS []byte
