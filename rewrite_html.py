import re

with open('internal/report/reporter.go', 'r', encoding='utf-8') as f:
    content = f.read()

# 1. Logo
content = content.replace(
    '<div class=\"brand\">TRICERA AUDIT ENGINE v5.3 — FULL CAPABILITY REPORT</div>',
    '<div class=\"brand\" style=\"display:flex; align-items:center;\"><span style=\"font-size: 32px; margin-right: 10px; filter: hue-rotate(80deg);\">??</span>TRICERA AUDIT ENGINE v5.3 — FULL CAPABILITY REPORT</div>'
)

# 2. Coverage tooltips
content = content.replace(
    '<div class=\"coverage-title\">??? Inventario del Activo</div>',
    '<div class=\"coverage-title\">??? Inventario del Activo</div><p style=\"font-size:12px; color:var(--text-dim); margin-bottom:15px;\">Muestra los componentes estructurales del equipo. Las interfaces y VLANs determinan el grado de segmentación interna física o lógica.</p>'
)
content = content.replace(
    '<div class=\"coverage-title\">??? Cobertura Técnica del Parser</div>',
    '<div class=\"coverage-title\">??? Cobertura Técnica del Parser</div><p style=\"font-size:12px; color:var(--text-dim); margin-bottom:15px;\">Elementos de seguridad procesados. Los Perfiles de Seguridad representan las inspecciones UTM activas (ej. Antivirus, IPS, Filtrado Web).</p>'
)

# 3. Object Hygiene Tooltip
obj_hygiene_target = '<!-- 8. OBJECT HYGIENE -->\n        <div id=\"obj-hygiene\" class=\"section-title\">?? Object Hygiene & Health</div>'
obj_hygiene_repl = '<!-- 8. OBJECT HYGIENE -->\n        <div id=\"obj-hygiene\" class=\"section-title\">?? Object Hygiene & Health</div>\n        <div class=\"ciso-tooltip\">\n            <strong>?? Business Impact:</strong> Mantener una higiene de objetos estricta evita la degradación del rendimiento del firewall. Los <strong>Servicios Personalizados</strong> son puertos no estándar que a menudo se usan para evadir controles (ej. P2P o minería). Los <strong>Objetos Huérfanos</strong> son reglas abandonadas que consumen memoria RAM y complican las auditorías.\n        </div>'
content = content.replace(obj_hygiene_target, obj_hygiene_repl)

# 4. FW Intel Rewrite
fw_intel_target = re.search(r'<!-- 6\. FIREWALL POLICY INTELLIGENCE -->.*?{{end}}\n        {{end}}', content, re.DOTALL)
if fw_intel_target:
    new_fw_intel = '''<!-- 6. FIREWALL POLICY INTELLIGENCE -->
        <div id="fw-intel" class="section-title">??? Firewall Policy Intelligence</div>
        {{range  := .FindingGroups}}
            {{if eq .Category "FW-INTEL"}}
            <div class="card">
                <div style="display:flex; justify-content:space-between; margin-bottom:15px;">
                    <h3>{{.Title}}</h3>
                    <span class="badge badge-danger">{{.Severity}}</span>
                </div>
                <p style="font-size:13px; color:var(--warn); margin-bottom:15px;"><strong>?? Impacto en el Negocio:</strong> {{.BusinessImpact}}</p>
                <table class="data-table">
                    <thead>
                        <tr>
                            <th>Policy ID / VDOM</th>
                            <th>Línea</th>
                            <th>Configuración Detectada</th>
                            <th>Sugerencia Técnica</th>
                        </tr>
                    </thead>
                    <tbody>
                        {{range .AffectedItems}}
                        <tr>
                            <td><strong>ID: {{.PolicyID}}</strong><br><small>{{.VDOM}}</small></td>
                            <td>{{.Line}}</td>
                            <td><code class="evidence-text">{{.Evidence}}</code></td>
                            <td>{{.Recommended}}</td>
                        </tr>
                        {{end}}
                    </tbody>
                </table>
            </div>
            {{end}}
        {{end}}'''
    content = content.replace(fw_intel_target.group(0), new_fw_intel)

# 5. Appendix details
appendix_target = re.search(r'<!-- 11\. APÉNDICE TÉCNICO -->\n        <div id="appendix" class="section-title">?? Apéndice Técnico de Evidencias \(Master List\)</div>\n        <div class="card">\n            <table class="data-table">', content, re.DOTALL)
if appendix_target:
    content = content.replace(appendix_target.group(0), '<!-- 11. APÉNDICE TÉCNICO -->\n        <div id="appendix" class="section-title">?? Apéndice Técnico de Evidencias (Master List)</div>\n        <div class="card">\n            <details><summary style="cursor:pointer; font-weight:800; font-size:16px; color:var(--primary); padding:10px;">Desplegar Lista Completa de Evidencias Brutas</summary><div style="margin-top:20px;">\n            <table class="data-table">')
    
    end_appendix = re.search(r'</table>\n        </div>\n\n        <footer>', content)
    if end_appendix:
        content = content.replace(end_appendix.group(0), '</table>\n            </div></details>\n        </div>\n\n        <footer>')

# 6. CIS Rename
content = content.replace('"NET": {ID: "NET", Name: "Interfaces y Servicios", Icon: "??"}', '"NET": {ID: "NET", Name: "Interfaces y Servicios Expuestos", Icon: "??"}')
content = content.replace('"IAM": {ID: "IAM", Name: "Administración e Identidad", Icon: "??"}', '"IAM": {ID: "IAM", Name: "Identidad y Control de Acceso Perimetral", Icon: "??"}')
content = content.replace('"SEC": {ID: "SEC", Name: "Auditoría de Políticas", Icon: "???"}', '"SEC": {ID: "SEC", Name: "Auditoría Avanzada de Políticas", Icon: "???"}')
content = content.replace('"MGMT": {ID: "MGMT", Name: "Gestión y Logging", Icon: "???"}', '"MGMT": {ID: "MGMT", Name: "Trazabilidad y Retención de Logs", Icon: "???"}')
content = content.replace('"SISTEMA": {ID: "SISTEMA", Name: "Hardening Global", Icon: "??"}', '"SISTEMA": {ID: "SISTEMA", Name: "Parámetros Base del Sistema", Icon: "??"}')

# 7. Policy Inventory disclaimer
content = content.replace('Inventario exhaustivo de todas las políticas de firewall activas e inactivas procesadas en la configuración de la sucursal <strong>{{.Hostname}}</strong>:</p>', 'Inventario exhaustivo de todas las políticas de firewall activas e inactivas procesadas en la configuración de la sucursal <strong>{{.Hostname}}</strong>.<br><em style="color:var(--warn); font-size:12px;">Nota: Solo se listan reglas explícitas (IPv4/IPv6 L4). El Parser no extrae reglas implícitas o de sistema operativo.</em></p>')

# 8. Reorder GRC to Section 3
# Find the entire COMPLIANCE block
grc_block = re.search(r'<!-- 9\. COMPLIANCE MAPPING -->.*?</div>\n                </div>\n            </div>\n        </div>', content, re.DOTALL)
if grc_block:
    extracted_grc = grc_block.group(0)
    # Remove it from current location
    content = content.replace(extracted_grc, '')
    
    # Insert it after 2. EXECUTIVE SNAPSHOT block
    snapshot_end = re.search(r'<!-- 2\. EXECUTIVE SNAPSHOT -->.*?</div>\n        </div>\n', content, re.DOTALL)
    if snapshot_end:
        new_grc = '\\n\\n        <!-- 3. COMPLIANCE MAPPING (MOVED) -->\\n' + extracted_grc.replace('<!-- 9. COMPLIANCE MAPPING -->', '')
        content = content[:snapshot_end.end()] + new_grc + content[snapshot_end.end():]

with open('internal/report/reporter.go', 'w', encoding='utf-8') as f:
    f.write(content)

print("HTML template successfully updated via python script.")
