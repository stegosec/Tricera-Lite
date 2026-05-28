package system

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"tricera/internal/ui"

	"aead.dev/minisign"
)

// Version se inyecta en tiempo de compilación con ldflags:
//
//	go build -ldflags "-X tricera/internal/system.Version=1.0.0"
var Version = "dev"

// DefaultUpdateURL es la URL base de GitHub Releases desde donde se descargan los binarios.
// SEC-FIX: Solo se permite HTTPS. Cambiar esta constante a tu URL de releases real.
const DefaultUpdateURL = "https://github.com/stegosec/Tricera-lite/releases/latest/download/"

// trustedPublicKey es la clave pública minisign embebida en el binario.
// Esta clave la controla el mantenedor del proyecto y se usa para verificar
// que el binario descargado no ha sido manipulado.
//
// INSTRUCCIONES PARA GENERAR TU PAR DE CLAVES:
//
//	minisign -G -p tricera.pub -s tricera.key
//
// Luego copia el contenido de tricera.pub aquí (es una sola línea que empieza con "RW...").
const trustedPublicKey = "RWT9fJt+9dlg3rK+erHXOAp5VSbpYyfn1mddmgtR6LmlBQ+mqoFWCJly"

// maxBinarySize limita el tamaño máximo del binario descargado a 200MB
// para prevenir ataques de agotamiento de disco/memoria (SEC-FIX: resource exhaustion).
const maxBinarySize = 200 * 1024 * 1024

// downloadTimeout limita el tiempo total de descarga para prevenir conexiones colgadas.
const downloadTimeout = 5 * time.Minute

// ──────────────────────────────────────────────────────────────────────────────
// PrintUpdateInstructions muestra cómo actualizar el binario manualmente según el OS.
// Se conserva como fallback para usuarios sin conectividad o que prefieran el proceso manual.
// ──────────────────────────────────────────────────────────────────────────────
func PrintUpdateInstructions() {
	ui.PrintInfo("Instrucciones de actualización manual (Versión actual: " + Version + ")")

	fmt.Printf("\n%sPASOS PARA ACTUALIZAR:%s\n", ui.Bold, ui.Reset)

	if runtime.GOOS == "windows" {
		fmt.Println("1. Descargar 'tricera.exe' y 'tricera.exe.minisig' desde el repositorio oficial de GitHub Releases (HTTPS).")
		fmt.Println("2. Validar firma: minisign -Vm tricera.exe -p tricera.pub")
		fmt.Println("3. Validar integridad en PowerShell: Get-FileHash .\\tricera.exe")
		fmt.Println("4. Renombrar el binario actual a 'tricera.old'.")
		fmt.Println("5. Mover el nuevo binario a la carpeta actual.")
		fmt.Println("6. Ejecutar 'tricera.exe -update' y verificar la versión.")
	} else {
		// SEC-FIX VULN-018: Instrucciones genéricas sin URLs hardcodeadas a dominios no controlados
		fmt.Println("1. Descargar el binario más reciente y su archivo .minisig desde GitHub Releases.")
		fmt.Println("2. Validar firma: minisign -Vm tricera -p tricera.pub")
		fmt.Println("3. sha256sum tricera  # Comparar con el hash publicado")
		fmt.Println("4. chmod +x tricera")
		fmt.Println("5. sudo mv tricera /usr/local/bin/")
	}

	fmt.Printf("\n%s[TIP]%s Para actualización automática y segura, usa: tricera -auto-update\n", ui.Bold+ui.Cyan, ui.Reset)
	fmt.Printf("\n%s¡Actualización completada exitosamente!%s\n", ui.Green, ui.Reset)
}

// ──────────────────────────────────────────────────────────────────────────────
// RunSecureUpdate ejecuta el flujo completo de auto-actualización segura.
//
// Capa 1: Descarga HTTPS estricta con validación TLS (certificados, TLS 1.2+)
// Capa 2: Cálculo de SHA-256 del binario descargado
// Capa 3: Verificación de firma asimétrica minisign con clave pública embebida
//
// Si cualquier capa falla, el archivo temporal se borra y la actualización se aborta.
// ──────────────────────────────────────────────────────────────────────────────
func RunSecureUpdate(baseURL string) error {
	ui.PrintInfo("Iniciando auto-actualización segura de Tricera...")
	ui.PrintInfo("Versión actual: " + Version)

	// ── Paso 0: Validar que la URL base sea HTTPS ──────────────────────────
	if err := validateHTTPS(baseURL); err != nil {
		return fmt.Errorf("validación de URL rechazada: %w", err)
	}

	// ── Determinar nombre del binario según OS y Arch ──────────────────────
	binaryName := fmt.Sprintf("tricera-%s-%s", runtime.GOOS, runtime.GOARCH)
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryURL := strings.TrimRight(baseURL, "/") + "/" + binaryName
	sigURL := binaryURL + ".minisig"

	// ── Capa 1: Descarga HTTPS estricta del binario ────────────────────────
	ui.PrintInfo("[Capa 1/3] Descargando binario por HTTPS con validación TLS estricta...")
	tmpBinaryPath, err := secureDownload(binaryURL)
	if err != nil {
		return fmt.Errorf("descarga segura del binario fallida: %w", err)
	}
	// Garantizar limpieza del temporal en CUALQUIER escenario de error
	defer func() {
		if _, statErr := os.Stat(tmpBinaryPath); statErr == nil {
			_ = os.Remove(tmpBinaryPath)
		}
	}()

	// ── Capa 1b: Descarga HTTPS estricta de la firma ───────────────────────
	ui.PrintInfo("[Capa 1/3] Descargando firma minisign por HTTPS...")
	tmpSigPath, err := secureDownload(sigURL)
	if err != nil {
		return fmt.Errorf("descarga segura de la firma fallida: %w", err)
	}
	defer func() {
		if _, statErr := os.Stat(tmpSigPath); statErr == nil {
			_ = os.Remove(tmpSigPath)
		}
	}()

	// ── Capa 2: Calcular SHA-256 del binario descargado ────────────────────
	ui.PrintInfo("[Capa 2/3] Calculando hash SHA-256 del binario descargado...")
	hashHex, err := computeSHA256(tmpBinaryPath)
	if err != nil {
		return fmt.Errorf("cálculo de SHA-256 fallido: %w", err)
	}
	ui.PrintInfo("SHA-256: " + hashHex)

	// ── Capa 3: Verificar firma minisign ───────────────────────────────────
	ui.PrintInfo("[Capa 3/3] Verificando firma criptográfica minisign...")
	if err := verifyMinisignSignature(tmpBinaryPath, tmpSigPath); err != nil {
		// SEC-FIX: Borrar INMEDIATAMENTE el binario no confiable
		_ = os.Remove(tmpBinaryPath)
		_ = os.Remove(tmpSigPath)
		return fmt.Errorf("VERIFICACIÓN DE FIRMA FALLIDA — actualización abortada: %w", err)
	}
	ui.PrintSuccess("Firma criptográfica verificada correctamente.")

	// ── Reemplazo atómico del ejecutable ───────────────────────────────────
	ui.PrintInfo("Reemplazando el ejecutable actual de forma segura...")
	if err := replaceExecutable(tmpBinaryPath); err != nil {
		return fmt.Errorf("reemplazo del ejecutable fallido: %w", err)
	}

	// Limpiar la firma temporal (el binario ya fue movido por replaceExecutable)
	_ = os.Remove(tmpSigPath)

	ui.PrintSuccess("Actualización completada exitosamente. Reinicia Tricera para usar la nueva versión.")
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// validateHTTPS valida estrictamente que la URL use el esquema HTTPS.
// SEC-FIX: Rechaza HTTP, FTP, o cualquier otro protocolo inseguro.
// ──────────────────────────────────────────────────────────────────────────────
func validateHTTPS(rawURL string) error {
	if !strings.HasPrefix(strings.ToLower(strings.TrimSpace(rawURL)), "https://") {
		return fmt.Errorf(
			"SEC-BLOCK: solo se permiten URLs HTTPS para descargas de actualización. "+
				"URL rechazada: %q. Esto previene ataques Man-in-the-Middle (MitM)",
			rawURL,
		)
	}
	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// secureDownload descarga un archivo por HTTPS con configuración TLS endurecida:
//   - TLS 1.2 como versión mínima obligatoria
//   - Validación completa de certificados (InsecureSkipVerify = false)
//   - Timeout total de 5 minutos para prevenir conexiones colgadas
//   - Límite de tamaño de 200MB para prevenir agotamiento de recursos
//
// Retorna la ruta al archivo temporal descargado.
// ──────────────────────────────────────────────────────────────────────────────
func secureDownload(url string) (string, error) {
	// SEC-FIX: Doble validación de HTTPS (defensa en profundidad)
	if err := validateHTTPS(url); err != nil {
		return "", err
	}

	// SEC-FIX: Configuración TLS endurecida
	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: false, // SEC-FIX: NUNCA deshabilitar verificación de certificados
	}

	client := &http.Client{
		Timeout: downloadTimeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
			// SEC-FIX: No seguir redirects a HTTP
			// (se valida en CheckRedirect)
		},
		// SEC-FIX: Verificar que los redirects también sean HTTPS
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if req.URL.Scheme != "https" {
				return fmt.Errorf("SEC-BLOCK: redirect a protocolo inseguro rechazado: %s", req.URL.String())
			}
			if len(via) >= 10 {
				return fmt.Errorf("SEC-BLOCK: demasiados redirects (posible ataque de redirect loop)")
			}
			return nil
		},
	}

	resp, err := client.Get(url)
	if err != nil {
		return "", fmt.Errorf("error de conexión HTTPS: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("servidor respondió con código HTTP %d (esperado 200 OK)", resp.StatusCode)
	}

	// SEC-FIX: Limitar el tamaño de la lectura para prevenir agotamiento de memoria/disco
	limitedReader := io.LimitReader(resp.Body, maxBinarySize+1)

	// Crear archivo temporal en el directorio del ejecutable actual
	execDir, err := getExecutableDir()
	if err != nil {
		return "", fmt.Errorf("no se pudo determinar el directorio del ejecutable: %w", err)
	}

	tmpFile, err := os.CreateTemp(execDir, "tricera-update-*.tmp")
	if err != nil {
		return "", fmt.Errorf("no se pudo crear archivo temporal: %w", err)
	}
	tmpPath := tmpFile.Name()

	written, err := io.Copy(tmpFile, limitedReader)
	tmpFile.Close() // Cerrar antes de verificar errores para liberar el fd

	if err != nil {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("error escribiendo archivo temporal: %w", err)
	}

	if written > maxBinarySize {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("SEC-BLOCK: el archivo descargado excede el límite de %dMB (posible ataque)", maxBinarySize/(1024*1024))
	}

	if written == 0 {
		_ = os.Remove(tmpPath)
		return "", fmt.Errorf("SEC-BLOCK: el archivo descargado está vacío (0 bytes)")
	}

	ui.PrintSuccess(fmt.Sprintf("Descarga completada: %d bytes → %s", written, filepath.Base(tmpPath)))
	return tmpPath, nil
}

// ──────────────────────────────────────────────────────────────────────────────
// computeSHA256 calcula el hash SHA-256 de un archivo y retorna su representación hex.
// ──────────────────────────────────────────────────────────────────────────────
func computeSHA256(filePath string) (string, error) {
	f, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("no se pudo abrir el archivo para hashear: %w", err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("error calculando SHA-256: %w", err)
	}

	return hex.EncodeToString(h.Sum(nil)), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// verifyMinisignSignature verifica la firma minisign del binario descargado
// usando la clave pública embebida (trustedPublicKey).
//
// SEC-FIX: Si la firma no es válida, retorna un error y el caller debe borrar
// el archivo temporal INMEDIATAMENTE.
// ──────────────────────────────────────────────────────────────────────────────
func verifyMinisignSignature(binaryPath, sigPath string) error {
	// Parsear la clave pública embebida
	var pubKey minisign.PublicKey
	if err := pubKey.UnmarshalText([]byte(trustedPublicKey)); err != nil {
		return fmt.Errorf("la clave pública minisign embebida es inválida (error de configuración): %w", err)
	}

	// Leer el contenido del binario descargado
	binaryContent, err := os.ReadFile(binaryPath)
	if err != nil {
		return fmt.Errorf("no se pudo leer el binario para verificar: %w", err)
	}

	// Leer la firma como bytes sin procesar (minisign.Verify espera []byte)
	sigContent, err := os.ReadFile(sigPath)
	if err != nil {
		return fmt.Errorf("no se pudo leer el archivo de firma .minisig: %w", err)
	}

	// SEC-FIX: Verificación criptográfica asimétrica
	// minisign.Verify parsea internamente la firma y valida contra la clave pública
	if !minisign.Verify(pubKey, binaryContent, sigContent) {
		return fmt.Errorf(
			"SEC-BLOCK: LA FIRMA CRIPTOGRÁFICA NO COINCIDE. " +
				"El binario descargado puede haber sido manipulado o corrompido. " +
				"No se instalará. Contacta al mantenedor del proyecto",
		)
	}

	return nil
}

// ──────────────────────────────────────────────────────────────────────────────
// replaceExecutable reemplaza el ejecutable actual con el binario verificado.
//
// Proceso seguro:
//  1. Renombrar ejecutable actual → .old (backup)
//  2. Mover temporal verificado → ubicación del ejecutable
//  3. Si falla el paso 2, restaurar el backup
// ──────────────────────────────────────────────────────────────────────────────
func replaceExecutable(tmpPath string) error {
	currentExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("no se pudo determinar la ruta del ejecutable actual: %w", err)
	}

	// Resolver symlinks para obtener la ruta real
	currentExe, err = filepath.EvalSymlinks(currentExe)
	if err != nil {
		return fmt.Errorf("no se pudo resolver la ruta real del ejecutable: %w", err)
	}

	backupPath := currentExe + ".old"

	// Paso 1: Crear backup del ejecutable actual
	// Eliminar backup anterior si existe
	_ = os.Remove(backupPath)

	if err := os.Rename(currentExe, backupPath); err != nil {
		return fmt.Errorf("no se pudo crear backup del ejecutable actual: %w", err)
	}

	// Paso 2: Mover el binario verificado a la ubicación del ejecutable
	if err := os.Rename(tmpPath, currentExe); err != nil {
		// SEC-FIX: Restaurar el backup si falla el reemplazo
		ui.PrintWarning("Error al instalar nuevo binario. Restaurando backup...")
		if restoreErr := os.Rename(backupPath, currentExe); restoreErr != nil {
			return fmt.Errorf(
				"CRÍTICO: falló la instalación (%v) Y la restauración del backup (%v). "+
					"Restaura manualmente desde '%s'",
				err, restoreErr, backupPath,
			)
		}
		return fmt.Errorf("instalación fallida (backup restaurado): %w", err)
	}

	// Paso 3: En sistemas Unix, asegurar permisos de ejecución
	if runtime.GOOS != "windows" {
		if err := os.Chmod(currentExe, 0755); err != nil {
			ui.PrintWarning(fmt.Sprintf("No se pudieron establecer permisos de ejecución: %v", err))
		}
	}

	ui.PrintSuccess(fmt.Sprintf("Ejecutable reemplazado: %s", currentExe))
	ui.PrintInfo(fmt.Sprintf("Backup disponible en: %s", backupPath))
	return nil
}

// getExecutableDir retorna el directorio donde reside el ejecutable actual.
func getExecutableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}

// ──────────────────────────────────────────────────────────────────────────────
// CleanupPreviousUpdate busca y elimina silenciosamente el archivo .old
// que queda como backup de una actualización previa. Debe llamarse una vez
// durante la inicialización de main() para no acumular basura en el sistema.
//
// Es deliberadamente silenciosa: si el archivo no existe o no se puede borrar,
// no interrumpe la ejecución normal del programa.
// ──────────────────────────────────────────────────────────────────────────────
func CleanupPreviousUpdate() {
	exe, err := os.Executable()
	if err != nil {
		return
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return
	}

	oldPath := exe + ".old"
	if _, err := os.Stat(oldPath); err == nil {
		_ = os.Remove(oldPath)
	}
}
