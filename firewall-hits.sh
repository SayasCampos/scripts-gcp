#!/bin/bash

# Valida que se haya pasado jq
if ! command -v jq &> /dev/null
then
    echo "Error: El comando 'jq' no está instalado. Por favor, instálalo para continuar."
    exit 1
fi

# --- Configuración ---
# Lista de IDs de Organización a analizar (como en tu script de buckets)
ORG_IDS=("") # <-- PON AQUÍ TUS IDs DE CARPETAS Y FOLDERS 

MAX_DAYS_INACTIVE=60
CSV_FILE="firewall_report_consolidado_$(date +%Y%m%d).csv"

# --- Funciones Auxiliares (las mismas que ya hemos validado) ---
get_protocols_ports() {
    local rule_name="$1"
    local project_id="$2"
    gcloud compute firewall-rules describe "$rule_name" \
        --project="$project_id" --format="json" 2>/dev/null | \
        jq -r '[.allowed[]? | .IPProtocol as $proto | (.ports[]? // "all") | "\($proto):\(.)"] | join(", ")'
}
check_firewall_activity() {
    local rule_name="$1"; local network_name="$2"; local logs_enabled="$3"; local project_id="$4"
    if [ "$logs_enabled" != "YES" ]; then echo ",,,"; return; fi
    local log_filter="logName=\"projects/$project_id/logs/compute.googleapis.com%2Ffirewall\" AND (jsonPayload.rule_details.reference=\"network:$network_name/firewall:$rule_name\" OR jsonPayload.rule_name=\"$rule_name\")"
    local last_hit=$(gcloud logging read "$log_filter" --project="$project_id" --freshness="365d" --limit=1 --format="value(timestamp)" --order="DESC" 2>/dev/null | head -1)
    if [ -z "$last_hit" ]; then echo ",,,"; return; fi
    local current_unix=$(date +%s); local last_hit_unix=$(date -d "$last_hit" +%s 2>/dev/null)
    if [ -z "$last_hit_unix" ]; then echo "$last_hit,,,"; return; fi
    local days_inactive=$(( (current_unix - last_hit_unix) / 86400 )); local in_disuse="NO"
    if [ $days_inactive -ge $MAX_DAYS_INACTIVE ]; then in_disuse="YES"; fi
    local hit_count_raw=$(gcloud logging read "$log_filter" --project="$project_id" --format="value(timestamp)" --freshness="90d" --limit=1001 2>/dev/null | wc -l)
    local hit_count="$hit_count_raw"; if [ "$hit_count_raw" -gt 1000 ]; then hit_count="1000+"; fi
    echo "$last_hit,$days_inactive,$in_disuse,$hit_count"
}

# --- Lógica Principal ---

# Escribir el encabezado del CSV, SOLO si el archivo no existe aún.
if [ ! -f "$CSV_FILE" ]; then
    echo "Creando nuevo archivo de reporte: $CSV_FILE"
    echo "ProjectID,Name,Status,Type,Targets,Filters,Protocols/Ports,Action,Priority,Network,Logs Enabled,Last Hit,Days Inactive,In Disuse,Hit Count (90d)" > "$CSV_FILE"
fi

# Iterar sobre cada ID de Organización definido en el array ORG_IDS
for ORG_ID in "${ORG_IDS[@]}"; do
    echo "==========================================================="
    echo "Iniciando análisis para la Organización: $ORG_ID"
    echo "==========================================================="
    
    # --- MÉTODO DE DESCUBRIMIENTO DE PROYECTOS (IDÉNTICO AL DE TU SCRIPT) ---
    projects_in_org=$(gcloud projects list --format="value(projectId)" --filter="parent.id=$ORG_ID AND lifecycleState=ACTIVE")

    if [ -z "$projects_in_org" ]; then
        echo "No se encontraron proyectos activos para esta organización."
        continue # Pasa a la siguiente organización
    fi

    # Iterar sobre cada proyecto encontrado en la organización
    for project_id in $projects_in_org; do
        echo "--- Procesando proyecto: $project_id ---"

        # Verificar si la API de Compute está habilitada
        if ! gcloud services list --project="$project_id" --filter="config.name=compute.googleapis.com" --format="value(config.name)" | grep -q "compute.googleapis.com"; then
            echo "    --> OMITIDO: La API de Compute no está habilitada."
            continue
        fi

        # Obtener las reglas de firewall
        firewall_rules_json=$(gcloud compute firewall-rules list --project="$project_id" --format="json" 2>/dev/null)
        
        if [ -z "$firewall_rules_json" ] || [ "$(echo "$firewall_rules_json" | jq 'length')" -eq 0 ]; then
            echo "    --> OMITIDO: No se encontraron reglas de firewall."
            continue
        fi
        
        echo "    --> Encontradas $(echo "$firewall_rules_json" | jq 'length') reglas. Analizando..."

        # Procesar cada regla (lógica que ya teníamos)
        echo "$firewall_rules_json" | jq -c '.[]' | while read -r rule; do
            name=$(echo "$rule" | jq -r '.name'); disabled=$(echo "$rule" | jq -r '.disabled'); #... y el resto de las variables
            # ... (el resto de la lógica interna del bucle es idéntica)
            status="ENABLED"; last_hit_formatted=""; days_inactive=""; in_disuse=""; hit_count=""
            if [ "$disabled" == "true" ]; then
                status="DISABLED"; last_hit_formatted="N/A (Disabled)"; days_inactive="N/A"; in_disuse="N/A"; hit_count="N/A"
            else
                direction=$(echo "$rule" | jq -r '.direction // "INGRESS"'); priority=$(echo "$rule" | jq -r '.priority'); network_name=$(echo "$rule" | jq -r '.network | split("/") | last'); action=$(echo "$rule" | jq -r 'if .denied then "deny" else "allow" end'); logs_enabled=$(echo "$rule" | jq -r '.logConfig.enable? // false | if . then "YES" else "NO" end')
                target_tags=$(echo "$rule" | jq -r '[.targetTags[]?] | join(",")'); target_sas=$(echo "$rule" | jq -r '[.targetServiceAccounts[]?] | join(",")'); targets=""; if [ -n "$target_tags" ]; then targets+="tags:$target_tags"; fi; if [ -n "$target_sas" ]; then targets+="${target_tags:+, }accounts:$target_sas"; fi; if [ -z "$targets" ]; then targets="all targets"; fi
                source_ranges=$(echo "$rule" | jq -r '[.sourceRanges[]?] | join(" ")'); source_tags=$(echo "$rule" | jq -r '[.sourceTags[]?] | join(" ")'); filters=""; if [ -n "$source_ranges" ]; then filters+="ranges:$source_ranges"; fi; if [ -n "$source_tags" ]; then filters+="${filters:+, }tags:$source_tags"; fi; if [ -z "$filters" ]; then filters="all sources"; fi
                protocols_ports=$(get_protocols_ports "$name" "$project_id"); if [ -z "$protocols_ports" ]; then protocols_ports="all protocols"; fi
                activity_info=$(check_firewall_activity "$name" "$network_name" "$logs_enabled" "$project_id"); last_hit=$(echo "$activity_info" | cut -d',' -f1); days_inactive=$(echo "$activity_info" | cut -d',' -f2); in_disuse=$(echo "$activity_info" | cut -d',' -f3); hit_count=$(echo "$activity_info" | cut -d',' -f4)
                if [ -n "$last_hit" ]; then last_hit_formatted=$(date -d "$last_hit" "+%Y-%m-%d %H:%M:%S" 2>/dev/null); fi
            fi
            echo "\"$project_id\",\"$name\",\"$status\",\"$direction\",\"$targets\",\"$filters\",\"$protocols_ports\",\"$action\",$priority,\"$network_name\",\"$logs_enabled\",\"$last_hit_formatted\",\"$days_inactive\",\"$in_disuse\",\"$hit_count\"" >> "$CSV_FILE"
        done
    done
done

echo ""
echo "################################################################"
echo "PROCESO FINALIZADO PARA TODAS LAS ORGANIZACIONES"
echo "################################################################"
