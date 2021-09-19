from hashlib import md5
from virus_total_apis import PublicApi
import comprobaciones

#FUNCION ENCARGADA DE OBTENER EL RESULTADO DE VIRUSTOTAL
def analiza(API_KEY, archivo):
    
    numero = 0
    comprobar_conexion = comprobaciones.comprobar_conexion()

    resultados = list()

    api = PublicApi(API_KEY)
    with open(archivo, "rb") as f:
        file_hash = md5(f.read()).hexdigest()
    response = api.get_file_report(file_hash)
  

    if comprobar_conexion == "Ok":                
        numero = response["results"]["positives"]
        resultados.append(numero)
        
    else: 
        numero = -1
        resultados.append(numero)



    return resultados



