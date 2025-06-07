#!/bin/bash

# Configuración del proyecto
GCP_PROJECT_ID="xertica-support-host"
MAX_DAYS_INACTIVE=60
CSV_FILE="firewall_report_$(date +%Y%m%d).csv"

# Función para obtener protocolos y puertos
get_protocols_ports() {
    local rule_name="$1"
    gcloud compute firewall-rules describe "$rule_name" \
        --format="json" \
        --project="$GCP_PROJECT_ID" 2>/dev/null | \
        jq -r '[.allowed[]? | .IPProtocol as $proto | (.ports[]? // "all") | "\($proto):\(.)"] | join(", ")' 2>/dev/null
}

# Función para verificar actividad de firewall
check_firewall_activity() {
    local rule_name="$1"
    local network_name="$2"
    local logs_enabled="$3"
    
    if [ "$logs_enabled" != "YES" ]; then
        echo ",,,"
        return
    fi
    
    # Filtro robusto que busca por referencia COMPLETA o solo por NOMBRE
    local log_filter="logName=\"projects/$GCP_PROJECT_ID/logs/compute.googleapis.com%2Ffirewall\" \
        AND (jsonPayload.rule_details.reference=\"network:$network_name/firewall:$rule_name\" OR jsonPayload.rule_name=\"$rule_name\")"

    # <-- ÚNICO CAMBIO: Añadido --freshness="365d" para buscar hasta 1 año atrás.
    last_hit=$(gcloud logging read "$log_filter" \
        --project="$GCP_PROJECT_ID" \
        --freshness="365d" \
        --limit=1 \
        --format="value(timestamp)" \
        --order="DESC" 2>/dev/null | head -1)
    
    if [ -z "$last_hit" ]; then
        echo ",,,"
        return
    fi
    
    current_unix=$(date +%s)
    last_hit_unix=$(date -d "$last_hit" +%s 2>/dev/null)
    
    if [ -z "$last_hit_unix" ]; then
        echo "$last_hit,,,,"
        return
    fi
    days_inactive=$(( (current_unix - last_hit_unix) / 86400 ))
    
    if [ $days_inactive -ge $MAX_DAYS_INACTIVE ]; then
        in_disuse="YES"
    else
        in_disuse="NO"
    fi
    
    # Este comando ya estaba correcto, busca los hits de los últimos 90 días.
    hit_count=$(gcloud logging read "$log_filter" \
        --project="$GCP_PROJECT_ID" \
        --format="value(timestamp)" \
        --freshness="90d" 2>/dev/null | wc -l)
        
    echo "$last_hit,$days_inactive,$in_disuse,$hit_count"
}

# --- El resto del script permanece idéntico ---

# Encabezado del CSV
echo "Name,Type,Targets,Filters,Protocols/Ports,Action,Priority,Network,Logs Enabled,Last Hit,Days Inactive,In Disuse,Hit Count (90d)" > $CSV_FILE

# Obtener y procesar todas las reglas de firewall del proyecto
echo "Obteniendo todas las reglas de firewall del proyecto $GCP_PROJECT_ID..."
gcloud compute firewall-rules list \
    --format=json \
    --project=$GCP_PROJECT_ID | jq -c '.[]' | while read -r rule; do
    
    name=$(echo "$rule" | jq -r '.name')
    direction=$(echo "$rule" | jq -r '.direction // "INGRESS"')
    priority=$(echo "$rule" | jq -r '.priority')
    network_name=$(echo "$rule" | jq -r '.network | split("/") | last')
    action=$(echo "$rule" | jq -r 'if .denied then "deny" else "allow" end')
    logs_enabled=$(echo "$rule" | jq -r '.logConfig.enable? // false | if . then "YES" else "NO" end')
    
    target_tags=$(echo "$rule" | jq -r '[.targetTags[]?] | join(",")')
    target_sas=$(echo "$rule" | jq -r '[.targetServiceAccounts[]?] | join(",")')
    targets=""
    [ -n "$target_tags" ] && targets+="tags:$target_tags"
    [ -n "$target_sas" ] && targets+="${target_tags:+, }accounts:$target_sas"
    [ -z "$targets" ] && targets="all targets"
    
    source_ranges=$(echo "$rule" | jq -r '[.sourceRanges[]?] | join(" ")')
    source_tags=$(echo "$rule" | jq -r '[.sourceTags[]?] | join(" ")')
    filters=""
    [ -n "$source_ranges" ] && filters+="ranges:$source_ranges"
    [ -n "$source_tags" ] && filters+="${filters:+, }tags:$source_tags"
    [ -z "$filters" ] && filters="all sources"
    
    protocols_ports=$(get_protocols_ports "$name")
    [ -z "$protocols_ports" ] && protocols_ports="all protocols"
    
    activity_info=$(check_firewall_activity "$name" "$network_name" "$logs_enabled")
    last_hit=$(echo "$activity_info" | cut -d',' -f1)
    days_inactive=$(echo "$activity_info" | cut -d',' -f2)
    in_disuse=$(echo "$activity_info" | cut -d',' -f3)
    hit_count=$(echo "$activity_info" | cut -d',' -f4)
    
    if [ -n "$last_hit" ]; then
        last_hit_formatted=$(date -d "$last_hit" "+%Y-%m-%d %H:%M:%S" 2>/dev/null)
    else
        last_hit_formatted=""
    fi
    
    echo "\"$name\",\"$direction\",\"$targets\",\"$filters\",\"$protocols_ports\",\"$action\",$priority,\"$network_name\",\"$logs_enabled\",\"$last_hit_formatted\",\"$days_inactive\",\"$in_disuse\",\"$hit_count\"" >> $CSV_FILE
    
    echo "Procesada regla: $name | Red: $network_name | Logs: $logs_enabled | Último hit: ${last_hit_formatted:-N/A}"
done

echo ""
echo "################################################################"
echo " REPORTE COMPLETADO"
echo "################################################################"
echo " Proyecto analizado: $GCP_PROJECT_ID"
echo " Umbral de inactividad: $MAX_DAYS_INACTIVE días"
echo " Reporte generado en: $CSV_FILE"
echo "################################################################"
