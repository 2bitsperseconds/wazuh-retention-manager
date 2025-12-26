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
                                            files_to_delete.append(file_path)
                                        else:
                                            log(f"    Archivo dentro del rango de retención: {file_path}", "DEBUG")
                                    except Exception as e:
                                        log(f"    Fallo al procesar fecha en archivo {filename}: {e}", "ERROR")
    else:
        log(f"El directorio base '{base_dir}' no existe. Verifica la ruta.", "ERROR")
    return files_to_delete

def dry_run():
    log("Ejecutando en modo simulación (dry-run)...", "INFO")
    files = get_files_to_delete()
    log("\nArchivos que serían eliminados:", "INFO")
    for f in files:
        print(f"  {f}")
    log(f"Total: {len(files)} archivos marcados para eliminación.", "INFO")

def purge_old_alerts():
    log("Ejecutando purga real de archivos...", "INFO")
    files = get_files_to_delete()
    deleted_files_count = 0
    for f in files:
        try:
            os.remove(f)
            log(f"Archivo eliminado: {f}", "INFO")
            deleted_files_count += 1
        except Exception as e:
            log(f"No se pudo eliminar {f}: {e}", "ERROR")
    log(f"Se han eliminado {deleted_files_count} archivos anteriores a {cutoff_date.strftime('%Y-%m-%d')}", "INFO")

# Punto de entrada
if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python3 wazuh_retention.py [dry-run|purge]")
        sys.exit(1)

    mode = sys.argv[1]
    if mode == "dry-run":
        dry_run()
    elif mode == "purge":
        purge_old_alerts()
    else:
        print("Modo inválido. Usa 'dry-run' o 'purge'.")
