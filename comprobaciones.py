import requests
     

#COMPROBAR CONEXION CON VIRUSTOTAL
def comprobar_conexion():

    existe_conexion = "Refuse"
    
    try:
        response = requests.get("https://www.virustotal.com")
        existe_conexion = "Ok"
        
    except:
        pass

    return existe_conexion