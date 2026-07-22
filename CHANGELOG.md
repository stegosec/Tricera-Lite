# Changelog

Todos los cambios notables de este proyecto serán documentados en este archivo.

## [v0.1.1] - 2026-07-22

### Added
- **Terminal User Interface (TUI):** Implementada una interfaz gráfica interactiva de alto rendimiento impulsada por Bubble Tea (temática Hacker) para realizar operaciones tácticas sin usar parámetros CLI.
- **Soporte para Múltiples Unidades (Windows):** Opción manual (`p`) para insertar rutas absolutas de configuración saltando restricciones de FilePicker en volúmenes lógicos.
- **Generación Automática HTML:** Ejecutar Tricera en la TUI despliega la opción de generar y exportar reportes físicos (`.html`) en la ruta actual sin requerir flags.
- **Navegación Visual Dinámica:** Se agregaron atajos interactivos (`Esc`, `Up`, `Down`) en los flujos de la terminal.

### Changed
- **Orquestador Híbrido:** Refactorización de `cmd/tricera/main.go` implementando `x/term` para detectar dinámicamente si se ejecuta por humanos (TTY) o en un pipeline de CI/CD (Bypass CLI) asegurando 100% de compatibilidad.
- **Inteligencia de Amenazas Lock-Free:** Migración del `CircuitBreaker` de `sync.Mutex` a operaciones atómicas (`sync/atomic`), eliminando la inanición de hilos y mejorando enormemente la concurrencia en consultas PSIRT/KEV.

### Fixed
- **OS Pipe Deadlocks:** Solucionado el congelamiento del motor causado por el límite del buffer en Windows (64KB) implementando Goroutines de vaciado asíncrono.
- **Limpieza Criptográfica Segura:** Se inyectaron cierres deferidos (`defer func() { recover() }`) en el Updater garantizando que el malware o binarios truncados se borren del disco incluso ante Panics críticos del Go runtime.
- **Cadena de Suministro (CVE):** Se actualizó `golang.org/x/crypto` (v0.54.0) y `golang.org/x/net` (v0.57.0) mitigando más de 10 vulnerabilidades críticas reportadas (Autenticaciones rotas y Denegación de servicio).
