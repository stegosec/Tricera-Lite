# 🦖 Tricera - Firmware Hardening Engine
> **Tactical & Offline FortiOS Security Audit Engine by StegoSec**

[![Go Version](https://img.shields.io/badge/Language-Go%201.25-00ADD8?style=for-the-badge&logo=go&logoColor=white)](https://go.dev)
[![SAST Security](https://img.shields.io/badge/SAST--Audit-PASS-brightgreen?style=for-the-badge&logo=shield)](https://github.com/stegosec/Tricera-lite)
[![License](https://img.shields.io/badge/License-MIT-blue?style=for-the-badge)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey?style=for-the-badge)](https://github.com/stegosec/Tricera-lite/releases)

---

## 🚀 Visión General

**Tricera** es una herramienta de auditoría táctica e inteligencia de amenazas offline en consola diseñada por la comunidad de **StegoSec** para analizar y diagnosticar de forma inmediata la higiene, el robustecimiento y la superficie de exposición de configuraciones de firewalls **FortiOS (`.conf`)**.

Construido en **Go**, destaca por su enfoque de **Fricción Cero**: un único binario nativo, auto-contenido, ultrarrápido y sin dependencias externas. A partir de la versión `v0.1.1`, Tricera integra una potente **Terminal User Interface (TUI)** de temática hacker y un sistema asíncrono **Lock-Free**, elevando el rendimiento de escaneo al máximo nivel.

---

## ✨ Novedades de la Versión v0.1.1

Esta versión es un hito monumental (Release Mayor) que aborda importantes rediseños arquitectónicos y mitigaciones de seguridad crítica:
* **Terminal User Interface (TUI):** Despliegue de entorno gráfico (Bubble Tea) con navegación interactiva para humanos, preservando el clásico CLI Bypass para pipelines CI/CD.
* **Higiene en la Cadena de Suministro (SCA):** Remediación de **+14 CVEs críticos** mitigando fallos de Denegación de Servicio y Bypass de Autenticación actualizando la *Standard Library* (`govulncheck`), y `golang.org/x/crypto`.
* **Lock-Free Concurrency:** Eliminación de cuellos de botella de hilos (Mutex) a favor de operaciones atómicas (`sync/atomic`) acelerando la inteligencia PSIRT/KEV.
* **OS Deadlock Fix:** Resolución de cuelgues de memoria causados por la saturación del buffer nativo de Windows (64KB).

> 📘 **Ver todos los detalles:** Consulta el archivo [CHANGELOG.md](CHANGELOG.md) en la raíz del repositorio.

---

## ✨ Características de Impacto (Elite Suite)

### 💻 1. TUI Hacker Interactiva
Tricera redefine la experiencia. Al ejecutarse sin parámetros, despliega una **interfaz gráfica interactiva (TUI)** impulsada por *Bubble Tea*. Navega por tus directorios visualmente, escoge tus configuraciones, define el tipo de escaneo e imprime el reporte localmente.  
*¿Usas pipelines automatizados (CI/CD)?* Tricera mantiene 100% de compatibilidad mediante los flags CLI clásicos.

### 🔑 2. Auditoría de Robustez de Hashes (Crypto-Audit)
Detecta de forma inteligente si el firewall usa algoritmos heredados débiles como el cifrado XOR reversible **`ENC`** de Fortinet para claves administrativas y VPNs, previniendo descifrados offline si tu archivo de respaldo llega a manos equivocadas.

### 🧠 3. Inteligencia de Red e Higiene
* **Shadowing:** Detecta políticas inalcanzables que generan brechas y deuda técnica.
* **Higiene de Objetos:** Rastrea objetos duplicados que comparten la misma IP/máscara o puertos redundantes.
* **Exposición Crítica:** Alerta si el plano administrativo (HTTPS, SSH) está abierto a la WAN, o si DMZ fluye libremente hacia la LAN.

### 👾 4. Cruzamiento CISA KEV & FortiGuard PSIRT (Lock-Free)
Cruza automáticamente el firmware detectado con la base oficial de vulnerabilidades activas de la **CISA (KEV)** y avisos de seguridad de **FortiGuard**. En modo Live, utiliza tecnología *Lock-Free Concurrency* (`sync/atomic`) para descargar inteligencia a velocidad asíncrona sin deadlocks.

### 🛡️ 5. Auto-Update Seguro con Firma Criptográfica (Minisign)
Actualiza tu herramienta a la última versión disponible en un solo comando (`tricera -auto-update`). Tricera descargará el binario directamente desde los *Releases* oficiales validando estáticamente las **Firmas Criptográficas Ed25519** mediante Minisign. ¡Sin malware en la cadena de suministro!

---

## 🛠️ Instalación (Binario Precompilado)

Si no tienes Go instalado, la instalación es inmediata.

**1. Descarga el Binario (Releases):**
Visita la pestaña [Releases](https://github.com/stegosec/Tricera-lite/releases) y descarga el ejecutable correspondiente a tu sistema (Windows, Linux, macOS ARM64/AMD64).

**2. Ejecuta Tricera:**
* **Windows:**
  Dale doble clic a `tricera.exe` o ábrelo en consola:
  ```powershell
  .\tricera.exe
  ```
* **Linux / macOS:**
  Abre la terminal, otorga permisos y ejecuta:
  ```bash
  chmod +x tricera
  ./tricera
  ```

---

## 💻 Guía de Uso (Pipeline y Automatización)

Aunque la TUI es excelente para humanos, Tricera brilla en flujos desatendidos (CLI Bypass Mode).

### Auditoría Básica Silenciosa
Genera un análisis local rápido mostrando al dinosaurio progresar:
```bash
./tricera -file mi_archivo_fortigate.conf
```

### Reporte Ejecutivo HTML en Vivo
Cruza la configuración con bases de datos globales (`live`) y exporta un documento HTML visualmente interactivo ideal para juntas directivas:
```bash
./tricera -file mi_archivo_fortigate.conf -intel-source live -format html -out reporte_ejecutivo.html
```

### Opciones Disponibles
```text
[ Parámetros de Auditoría ]
  -file <ruta>          Archivo .conf del FortiGate a auditar (Requerido en CI/CD)
  -format <formato>     Formato del reporte: text, json, html (por defecto: text)
  -out <ruta>           Archivo de salida para el reporte
  -compare <ruta>       Archivo .conf anterior para análisis diferencial
  -rules <ruta>         Archivo JSON con reglas de hardening personalizadas

[ Mantenimiento ]
  -auto-update          Actualización automática asegurada con criptografía Minisign
  -version              Imprime la versión actual del motor

[ Inteligencia PSIRT ]
  -intel-source <modo>  'offline' (Catálogo local ultrarrápido) o 'live' (Sincronización web PSIRT profunda)
```

---

## 📊 Arquitectura Limpia

El proyecto está diseñado bajo un modelo modular (cero acoplamiento):

```text
Tricera-lite
├── cmd/tricera/         # Entrypoint (Detección de TTY vs CI/CD)
├── internal/
│   ├── engine/          # Motor de evaluación y Machine Learning heurístico
│   ├── intelligence/    # Parseo de PSIRT y CISA KEV (Modelo asíncrono Lock-Free)
│   ├── parser/          # AST Parser lineal O(N) ultra veloz de FortiOS
│   ├── report/          # Renderización a Consola, JSON y HTML
│   ├── system/          # Auto-updater validado con claves públicas Minisign
│   ├── tui/             # Interfaz visual interactiva nativa (Bubble Tea)
│   └── ui/              # Framework de mensajes ANSI
└── tests/               # Laboratorio DevSecOps de pruebas de estrés
```

---

## 🛡️ DevSecOps & Shift-Left Security

Tricera es analizado por los más altos estándares de calidad antes de cada lanzamiento:
* **Dependencias Blindadas:** El pipeline cuenta con integraciones de `govulncheck` nativas de Google bloqueando la compilación ante cualquier vulnerabilidad en la cadena de suministro o Standard Library.
* **Cero inyección de comandos:** Sanitización rigurosa para generadores CLI.
* **Gestión de Memoria (Panic-Safe):** Rutinas `defer recover()` aseguran la destrucción de archivos de memoria incluso si el kernel interrumpe los procesos criptográficos subyacentes.

---

<div align="center">
  <p>Desarrollado con ❤️ por la comunidad de <strong>StegoSec Threat Intelligence</strong></p>
</div>
