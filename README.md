# 🦖 Tricera - Firmware Hardening Engine
> **Tactical & Offline FortiOS Security Audit Engine by StegoSec**

[![Go Version](https://img.shields.io/badge/Language-Go%201.24-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![SAST Security](https://img.shields.io/badge/SAST--Audit-PASS-brightgreen?style=for-the-badge&logo=shield)](https://github.com/stegosec/Tricera-lite)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey?style=for-the-badge)](https://github.com/stegosec/Tricera-lite/releases)

---

## 🚀 Visión General

**Tricera** es una herramienta de auditoría táctica e inteligencia de amenazas offline en consola diseñada por la comunidad de **StegoSec** para analizar y diagnosticar de forma inmediata la higiene, el robustecimiento y la superficie de exposición de configuraciones de firewalls **FortiOS (`.conf`)**.

Construido en **Go**, destaca por su enfoque de **Fricción Cero**: un único binario nativo, auto-contenido, ultrarrápido y sin dependencias de Python, Docker o servicios externos.

---

## ✨ Características de Impacto (Elite Suite)

### 🦕 1. Dynamic Dino-Driven Terminal Experience
Tricera redefine la experiencia en consola con un cargador porcentual interactivo de doble línea nativo. Observa al icónico **dinosaurio ASCII de 8 bits** (`🦖`/`🦕`) trotar dinámicamente y esquivar obstáculos en tiempo real al compás del progreso del análisis, culminando en un impacto explosivo (`💥🦖`) al completarse la auditoría con éxito.

```text
                                     🦕
  [👾 ANALIZANDO] [████████░░░░░░░░░░░░] 40%  Cargando catálogos CISA KEV y base PSIRT...
```

### 🔑 2. Auditoría de Robustez de Hashes (Crypto-Audit)
Detecta de forma inteligente si el firewall está usando algoritmos heredados débiles como el obsoleto cifrado XOR reversible **`ENC`** de Fortinet para claves administrativas y VPN pre-compartidas (PSK), previniendo ataques de descifrado offline inmediatos si tu archivo de respaldo se expone en la red.

### 🧠 3. Inteligencia de Red e Higiene de Objetos
* **Análisis de Reglas Sombreadas (Shadowing):** Detecta políticas inalcanzables que generan deuda técnica o brechas de seguridad humana.
* **Higiene de Base de Datos:** Rastrea objetos duplicados que comparten la misma dirección IP/máscara o puertos redundantes de servicios.
* **Detección de Exposición Crítica:** Alerta si el plano de control administrativo (HTTPS, SSH) está abierto directamente a la WAN pública o si la zona DMZ tiene flujos hiper-permisivos hacia la red LAN interna sin UTM activo.

### 👾 4. Cruzamiento CISA KEV & FortiGuard PSIRT
Cruza automáticamente la versión detectada de tu firmware con la base de datos oficial de vulnerabilidades conocidas explotadas activamente en la naturaleza de la **CISA (KEV)** y avisos de seguridad de **FortiGuard**, permitiendo auditorías 100% offline o en tiempo real (`live` mode).

---

## 🛠️ Instalación y Preparación

### 📥 Opción 1: Descargar Binario Precompilado (Recomendado - Sin Go)
Si no tienes Go instalado o prefieres no compilar, sigue la guía según tu sistema operativo:

#### 🪟 En Windows:
1. Ve a la pestaña de **Releases** en este repositorio de GitHub.
2. Descarga el archivo comprimido `tricera_windows_amd64.zip`.
3. Haz clic derecho y selecciona **Extraer todo**.
4. Abre la consola de **PowerShell** o **Símbolo del sistema** en esa carpeta.
5. Ejecuta tu primer análisis usando `.\tricera.exe`:
   ```powershell
   .\tricera.exe -file .\tu_archivo_config.conf
   ```

#### 🐧 En Linux / 🍎 macOS:
1. Descarga el archivo `tricera_linux_amd64.tar.gz` (o `tricera_darwin_arm64` si usas Mac M1/M2) desde la sección de **Releases**.
2. Abre tu terminal y descomprime el archivo:
   ```bash
   tar -xvf tricera_linux_amd64.tar.gz
   ```
3. **Paso Crucial:** Concede permisos de ejecución al binario:
   ```bash
   chmod +x tricera
   ```
4. Ejecuta el análisis directamente usando `./tricera`:
   ```bash
   ./tricera -file tu_archivo_config.conf
   ```

### 🛠️ Opción 2: Compilación Rápida (Para Desarrolladores)
Si tienes Go 1.24+ instalado y deseas compilar el código fuente tú mismo:
```powershell
# Clonar el código fuente
git clone https://github.com/stegosec/Tricera-lite.git
cd Tricera-lite

# Compilar binario optimizado
go build ./cmd/tricera
```

---

## 💻 Guía de Ejecución y Ejemplos Prácticos

### 1. Auditoría Estándar (Consola Interactiva 🦖)
Analiza un archivo de configuración local y muestra los resultados directamente en tu consola de manera gráfica y dinámica:
```powershell
# En Windows (PowerShell)
.\tricera.exe -file .\mi_archivo_fortigate.conf

# En Linux / macOS
./tricera -file mi_archivo_fortigate.conf
```

### 2. Reporte en Vivo e Informe HTML Interactivo (¡Espectacular! 📊)
Analiza el archivo local, consulta en tiempo real las APIs de FortiGuard para obtener los últimos boletines PSIRT de tu versión, y exporta un panel gráfico interactivo en formato HTML para entregar a clientes o directivos (CISO):
```powershell
# Ejecución en Windows (PowerShell)
.\tricera.exe -file .\mi_archivo_fortigate.conf -intel live -format html -out reporte_live.html

# Ejecución en Linux / macOS
./tricera -file mi_archivo_fortigate.conf -intel live -format html -out reporte_live.html
```

---

## ⚙️ Opciones Completas de la Interfaz CLI

```text
Opciones Generales:
  -file string          Ruta al archivo .conf de FortiGate a auditar (Requerido)
  -format string        Formato de salida del reporte: text, html, json (por defecto: text)
  -out string           Ruta de destino para guardar el reporte generado (ej: reporte.html)
  -compare string       Auditoría diferencial (diff) contra otro archivo .conf
  -intel string         Origen de inteligencia PSIRT: offline o live (por defecto: offline)
  -rules string         Ruta a un archivo .yaml personalizado con reglas adicionales
  -debug                Activa el modo detallado (verbose) del motor

Opciones de la Comunidad (StegoSec):
  -hardening-guide      Imprime una guía interactiva y accionable de robustecimiento de FortiOS
```

---

## 📊 Arquitectura Limpia

Tricera sigue un diseño modular y seguro de **deuda técnica cero**:

```text
c:\Users\paco\Documents\Tricera-lite
├── cmd/
│   └── tricera/         # Punto de entrada de la aplicación CLI
├── internal/
│   ├── engine/          # Motor de evaluación de hardening y reglas complejas
│   ├── intelligence/    # Parsers de base PSIRT offline local y live web feed
│   ├── matcher/         # Lógica de emparejamiento de CVEs y CISA KEV
│   ├── parser/          # AST Parser (Abstract Syntax Tree) lineal O(N) ultra veloz
│   ├── remediator/      # Generador automatizado de comandos CLI de mitigación
│   ├── report/          # Motores de renderizado (Consola, JSON, HTML Premium)
│   └── ui/              # Marcos de visualización ANSI y Dino Progress Bar
└── tests/               # Laboratorios de pruebas de configuraciones inseguras
```

---

## 🛡️ SAST & Auditoría de Seguridad
Tricera ha sido auditado mediante herramientas de análisis de seguridad estática, garantizando:
* **Previsión de Stack Overflow:** Máxima profundidad del AST acotada a un nivel rígido de recursión de 50.
* **Cero inyección de comandos:** Sanitización rigurosa de entradas y escapes de caracteres en scripts auto-generados.
* **Previsión de ReDoS:** Expresiones regulares precompiladas globalmente y limitadas.

---

## 📜 Licencia
Este proyecto es una iniciativa de código abierto para la comunidad global bajo la licencia **MIT**. 

---
<div align="center">
  <p>Desarrollado con ❤️ por la comunidad de <strong>StegoSec Threat Intelligence</strong></p>
</div>
