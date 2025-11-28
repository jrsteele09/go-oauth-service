package server

const (
	// Standard colors
	Black   = "\033[30m"
	Red     = "\033[31m"
	Green   = "\033[32m"
	Yellow  = "\033[33m"
	Blue    = "\033[34m"
	Magenta = "\033[35m"
	Cyan    = "\033[36m"
	White   = "\033[37m"
	Gray    = "\033[90m" // Bright black, often appears as gray

	// Inverse video colors
	BlackInverse   = "\033[7;30m"
	RedInverse     = "\033[7;31m"
	GreenInverse   = "\033[7;32m"
	YellowInverse  = "\033[7;33m"
	BlueInverse    = "\033[7;34m"
	MagentaInverse = "\033[7;35m"
	CyanInverse    = "\033[7;36m"
	WhiteInverse   = "\033[7;37m"
	GrayInverse    = "\033[7;90m" // Using bright black for gray in inverse

	ResetColor = "\033[0m" // Reset to default color
)

var methodColors = map[string]string{
	"GET":    Green,
	"POST":   Blue,
	"PUT":    Cyan,
	"DELETE": Yellow,
	"PATCH":  Magenta,
}
