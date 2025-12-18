
from src.misc.configread import ConfigReader

print("Cargando configuración OAuth desde SecConfig.json...")
config_reader = ConfigReader()
oauth_configs = config_reader.get_oauth_config()
if oauth_configs:
    print("Configuración OAuth cargada correctamente.")
    print(oauth_configs)
else:
    print("No se encontró configuración OAuth en SecConfig.json.")