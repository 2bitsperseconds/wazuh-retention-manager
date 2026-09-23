import os
import sys
import yaml
from datetime import datetime, timedelta
import re

# Cargar configuración desde archivo YAML
config_file = "/opt/wazuh-retention-manager/config.yml"
if not os.path.exists(config_file):
    print("[ERROR] Archivo de configuración 'config.yml' no encontrado.")
    sys.exit(1)

with open(config_file, 'r') as f:
    config = yaml.safe_load(f)

# Configuración desde YAML
retention_days = config.get("retention_days", 30)
log_level = config.get("log_level", "INFO").upper()
base_dir = config.get("base_dir", "/var/ossec/logs/alerts")
cutoff_date = datetime.now() - timedelta(days=retention_days)

# Expresión regular para archivos tipo ossec-alerts-<día>.<extensión>
filename_regex = re.compile(r"ossec-alerts-(\d{2})\.(json\.gz|log\.gz|log\.sum|json\.sum)$")

# Función de logging controlado por nivel
def log(message, level="INFO"):
    levels = ["DEBUG", "INFO", "WARN", "ERROR"]
    if levels.index(level) >= levels.index(log_level):
        print(f"[{level}] {message}")

def get_files_to_delete():
    files_to_delete = []

    log(f"Escaneando directorio base: {base_dir}", "INFO")
    if os.path.exists(base_dir):
        for year_folder in os.listdir(base_dir):
            year_path = os.path.join(base_dir, year_folder)
            if os.path.isdir(year_path):
                log(f"Año detectado: {year_folder}", "INFO")
                for month_folder in os.listdir(year_path):
                    month_path = os.path.join(year_path, month_folder)
                    if os.path.isdir(month_path):
                        log(f"  Mes detectado: {month_folder}", "INFO")
                        for filename in os.listdir(month_path):
                            file_path = os.path.join(month_path, filename)
                            if os.path.isfile(file_path):
                                match = filename_regex.match(filename)
                                if match:
                                    try:
                                        day = int(match.group(1))
                                        file_date_str = f"{year_folder}-{month_folder[:3]}-{day:02d}"
                                        file_date = datetime.strptime(file_date_str, "%Y-%b-%d")
                                        log(f"    Archivo: {filename} -> Fecha extraída: {file_date.strftime('%Y-%m-%d')}", "DEBUG")
                                        
                                        if file_date < cutoff_date:
                                            log(f"    Archivo marcado para eliminación: {file_path}", "WARN")
                                            # Modificado: Se añade una tupla con la ruta y la fecha
                                            files_to_delete.append((file_path, file_date))
                                        else:
                                            log(f"    Archivo dentro del rango de retención: {file_path}", "DEBUG")
                                    except Exception as e:
                                        log(f"    Fallo al procesar fecha en archivo {filename}: {e}", "ERROR")
    else:
        log(f"El directorio base '{base_dir}' no existe. Verifica la ruta.", "ERROR")
    return files_to_delete

def dry_run():
    log("Ejecutando en modo simulación (dry-run)...", "INFO")
    files_info = get_files_to_delete()
    
    json_gz_count = 0
    
    log("\nArchivos que serían eliminados:", "INFO")
    for f_path, f_date in files_info:
        print(f"  {f_path}")
        # Contamos específicamente los archivos .json.gz
        if f_path.endswith(".json.gz"):
            json_gz_count += 1
        
    log(f"Total general de archivos marcados para eliminación: {len(files_info)}", "INFO")
    log(f"Total de archivos 'ossec-alerts-*.json.gz' en frío a eliminar: {json_gz_count}", "INFO")

def purge_old_alerts():
    log("Ejecutando purga real de archivos...", "INFO")
    files_info = get_files_to_delete()
    deleted_files_count = 0
    for f_path, f_date in files_info:
        try:
            os.remove(f_path)
            log(f"Archivo eliminado: {f_path}", "INFO")
            deleted_files_count += 1
        except Exception as e:
            log(f"No se pudo eliminar {f_path}: {e}", "ERROR")
    log(f"Se han eliminado {deleted_files_count} archivos anteriores a {cutoff_date.strftime('%Y-%m-%d')}", "INFO")

def count_cold_logs():
    log(f"Contando archivos totales .json.gz en almacenamiento (base_dir: {base_dir})...", "INFO")
    
    # Diccionario para agrupar los resultados { "2023": {"Jan": 31, "Feb": 28}, ... }
    stats = {}
    total_count = 0
    
    if os.path.exists(base_dir):
        # Usamos sorted() para que los años salgan en orden
        for year_folder in sorted(os.listdir(base_dir)):
            year_path = os.path.join(base_dir, year_folder)
            if os.path.isdir(year_path):
                stats[year_folder] = {}
                
                for month_folder in os.listdir(year_path):
                    month_path = os.path.join(year_path, month_folder)
                    if os.path.isdir(month_path):
                        month_count = 0
                        for filename in os.listdir(month_path):
                            # Solo contamos los que cumplen con el patrón y son .json.gz
                            if filename.startswith("ossec-alerts-") and filename.endswith(".json.gz"):
                                month_count += 1
                        
                        # Solo guardamos el mes si tiene archivos
                        if month_count > 0:
                            stats[year_folder][month_folder] = month_count
                            total_count += month_count
    else:
        log(f"El directorio base '{base_dir}' no existe. Verifica la ruta.", "ERROR")
        return
    
    # Diccionario de meses para ordenar cronológicamente
    month_order = {
        "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, 
        "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, 
        "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12
    }

    # Impresión detallada y formateada
    print("\n" + "="*50)
    print("[RESULTADO] Detalle de archivos 'ossec-alerts-*.json.gz' en frío:")
    print("="*50)
    
    if total_count == 0:
        print("No se encontraron archivos en frío (.json.gz).")
    else:
        for year, months in stats.items():
            if months:  # Solo imprimimos si el año tiene datos
                print(f"\n📅 Año {year}:")
                year_subtotal = 0
                
                # Ordenar los meses de este año usando el diccionario de mapeo
                sorted_months = sorted(months.items(), key=lambda x: month_order.get(x[0][:3].capitalize(), 13))
                
                for month, count in sorted_months:
                    print(f"   ├─ Mes {month}: {count} archivos")
                    year_subtotal += count
                print(f"   └─ Subtotal {year}: {year_subtotal} archivos")
                
    print("\n" + "="*50)
    print(f"📦 TOTAL CONSOLIDADO: {total_count} archivos")
    print("="*50 + "\n")

# Punto de entrada
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 wazuh_retention.py [dry-run|purge|count-cold]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "dry-run":
        dry_run()
    elif mode == "purge":
        purge_old_alerts()
    elif mode == "count-cold":
        count_cold_logs()
    else:
        print("Modo inválido. Usa 'dry-run', 'purge' o 'count-cold'.")
