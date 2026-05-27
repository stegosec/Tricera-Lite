package ui

import (
	"fmt"
	"os"
	"time"
)

// BannerVersion es establecida por main() al inicio para que el banner
// muestre la versión real inyectada por ldflags, sin crear dependencia circular.
var BannerVersion = "dev"

const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Cyan   = "\033[36m"
	Bold   = "\033[1m"
)

// PrintSuccess imprime un mensaje de éxito en verde
func PrintSuccess(msg string) {
	fmt.Printf("%s[+] %s%s\n", Green, msg, Reset)
}

// PrintInfo imprime un mensaje informativo en cian
func PrintInfo(msg string) {
	fmt.Printf("%s[*] %s%s\n", Cyan, msg, Reset)
}

// PrintWarning imprime una advertencia en amarillo
func PrintWarning(msg string) {
	fmt.Printf("%s[!] %s%s\n", Yellow, msg, Reset)
}

// FatalError detiene la ejecución con un formato visual claro para el usuario
func FatalError(motivo, solucion string) {
	fmt.Fprintf(os.Stderr, "\n%s%s[ERROR FATAL]%s\n", Bold, Red, Reset)
	fmt.Fprintf(os.Stderr, "%sMotivo: %s%s\n", Bold, motivo, Reset)
	if solucion != "" {
		fmt.Fprintf(os.Stderr, "%sSugerencia: %s%s\n", Bold, solucion, Reset)
	}
	fmt.Fprintf(os.Stderr, "\n")
	os.Exit(1)
}

// PrintBanner imprime el dinosaurio Tricera y el encabezado del motor en la consola
func PrintBanner() {
	fmt.Printf("%s", Cyan)
	fmt.Println(`                                                        ..:.`)
	fmt.Println(`                                                      .-#%%*.`)
	fmt.Println(`                                    ....::::.       ..+%%%%%=.    .. .`)
	fmt.Println(`                               ..-=*%%%%%%%%%%%*-. .-%%%%%%#-. .-+.-=.`)
	fmt.Println(`  ..-=+***+=-..............:=*#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%=.`)
	fmt.Println(`  ....-+#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%-.`)
	fmt.Println(`         ...-+#%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%*-.`)
	fmt.Println(`              . .:-+*##%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%+:...`)
	fmt.Println(`                       ......-*%%%%%%%%%%%%%%%%%%%%%#*=:........:-:.`)
	fmt.Println(`                               .*%%%%%%%%%%%%%%%%%%%*..`)
	fmt.Println(`                              .+%%%%%=.:-++*%%%%%%%%#-.`)
	fmt.Println(`                             .#%%%#-..+%%%%=. .#%%%+..%%%%*.`)
	fmt.Println(`                             .+%%%%+...+%%%%#-. :%%%%#:..+%%%%+.`)
	fmt.Println(`                               ..          ..     ....    ..`)
	fmt.Printf("%s\n", Reset)
	fmt.Printf("          %s%sSTEGOSEC THREAT INTELLIGENCE SUITE%s\n", Bold, Green, Reset)
	fmt.Printf("          %sTRICERA - Firmware Hardening Engine v%s%s\n", Bold+Cyan, BannerVersion, Reset)
	fmt.Println("          ──────────────────────────────────────")
	fmt.Println()
}


// PrintHardeningGuide imprime una guía rápida de hardening en consola para la comunidad
func PrintHardeningGuide() {
	fmt.Printf("%s================================================================================%s\n", Cyan+Bold, Reset)
	fmt.Printf("           %sSTEGOSEC TRICERA — GUÍA RÁPIDA DE HARDENING PARA FORTIOS%s\n", Bold+Green, Reset)
	fmt.Printf("%s================================================================================%s\n\n", Cyan+Bold, Reset)
	fmt.Printf("Esta guía rápida te ayuda a asegurar tu FortiGate paso a paso desde la CLI:\n\n")

	fmt.Printf("%s[1] Asegurar el Acceso Administrativo (Deshabilitar Protocolos Inseguros)%s\n", Bold+Yellow, Reset)
	fmt.Printf("Transmitir credenciales en texto plano (HTTP/Telnet) es un riesgo crítico de red.\n")
	fmt.Printf("%s  config system global%s\n", Cyan, Reset)
	fmt.Printf("      set admin-port 8080      # Cambiar HTTP por defecto\n")
	fmt.Printf("      set admin-sport 8443     # Cambiar HTTPS por defecto\n")
	fmt.Printf("      set admin-ssh-port 2222  # Cambiar SSH por defecto\n")
	fmt.Printf("%s  end%s\n\n", Cyan, Reset)

	fmt.Printf("%s[2] Habilitar la Contraseña Maestra de Cifrado (Mitigar Hashes ENC Reversibles)%s\n", Bold+Yellow, Reset)
	fmt.Printf("Por defecto, FortiOS almacena contraseñas con cifrado débil y reversible 'ENC'.\n")
	fmt.Printf("Activar la contraseña maestra las cifra de forma segura usando AES-256:\n")
	fmt.Printf("%s  config system global%s\n", Cyan, Reset)
	fmt.Printf("      set private-key-encryption enable\n")
	fmt.Printf("%s  end%s\n", Cyan, Reset)
	fmt.Printf("  * Te solicitará ingresar una contraseña maestra del sistema.\n\n")

	fmt.Printf("%s[3] Forzar Bloqueo de Cuentas (Mitigar Fuerza Bruta)%s\n", Bold+Yellow, Reset)
	fmt.Printf("Configura un límite de intentos fallidos antes de bloquear al usuario administrativo:\n")
	fmt.Printf("%s  config system global%s\n", Cyan, Reset)
	fmt.Printf("      set admin-lockout-threshold 3\n")
	fmt.Printf("      set admin-lockout-duration 900  # Bloqueo por 15 minutos\n")
	fmt.Printf("%s  end%s\n\n", Cyan, Reset)

	fmt.Printf("%s[4] Limitar las Interfaces de Gestión (Trusted Hosts)%s\n", Bold+Yellow, Reset)
	fmt.Printf("Nunca expongas allowaccess HTTP/HTTPS/SSH a la WAN externa. Usa Trusted Hosts:\n")
	fmt.Printf("%s  config system admin%s\n", Cyan, Reset)
	fmt.Printf("      edit \"admin\"\n")
	fmt.Printf("          set trusthost1 192.168.1.0 255.255.255.0  # Solo la subred LAN de TI\n")
	fmt.Printf("      next\n")
	fmt.Printf("%s  end%s\n\n", Cyan, Reset)

	fmt.Printf("%s================================================================================%s\n", Cyan+Bold, Reset)
	fmt.Printf("  %sFórmula del Éxito: Audita constantemente con: tricera -file <config.conf>%s\n", Bold, Reset)
	fmt.Printf("%s================================================================================%s\n", Cyan+Bold, Reset)
}

var progressStarted = false

// PlayAuditProgressBarDino dibuja una barra de progreso interactiva de dos líneas con el dinosaurio corriendo arriba de la barra
func PlayAuditProgressBarDino(pct int, statusMsg string) {
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}

	barLength := 20
	filledLength := (pct * barLength) / 100
	emptyLength := barLength - filledLength

	bar := ""
	for i := 0; i < filledLength; i++ {
		bar += "█"
	}
	for i := 0; i < emptyLength; i++ {
		bar += "░"
	}

	// Dino corre de derecha a izquierda (mirando hacia la izquierda) para que se visualice corriendo hacia adelante.
	// Al 0% (filledLength = 0) inicia a la derecha: 18 + 20 = 38.
	// Al 100% (filledLength = 20) llega al extremo izquierdo: 18 + 0 = 18.
	offset := 18 + (barLength - filledLength)

	dinoSpaces := ""
	for i := 0; i < offset; i++ {
		dinoSpaces += " "
	}

	dinoLine := ""
	if pct == 100 {
		dinoLine = dinoSpaces + "💥🦖"
	} else {
		// Alternamos entre 🦖 y 🦕 según el porcentaje para animar las piernas corriendo
		if pct%2 == 0 {
			dinoLine = dinoSpaces + "🦖"
		} else {
			dinoLine = dinoSpaces + "🦕"
		}
	}

	// Si ya empezamos, subimos el cursor una línea para sobreescribir la línea superior del dino
	if progressStarted {
		fmt.Print("\x1b[1A\r\x1b[K") // Sube 1 línea y limpia la línea superior
	} else {
		progressStarted = true
	}

	// Imprimimos la línea del dinosaurio
	fmt.Println(dinoLine)

	// Imprimimos la línea de la barra de progreso
	if pct == 100 {
		fmt.Printf("\r  %s[🏆 COMPLETADO]%s [%s] %d%%  %-55s\n\n", Bold+Green, Reset, bar, pct, statusMsg)
		progressStarted = false // Reseteamos para futuros escaneos si los hay
	} else {
		fmt.Printf("\r  %s[👾 ANALIZANDO]%s [%s] %d%%  %-55s", Bold+Yellow, Reset, bar, pct, statusMsg)
	}

	// Pequeño retardo para dar el efecto de juego retro responsivo en la terminal
	time.Sleep(200 * time.Millisecond)
}
