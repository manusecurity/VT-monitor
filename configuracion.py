import sqlite3


#GUARDAR CONFIGURACION
def guardarConfiguracion(api_key, ruta, protegeme):

    guardado = False

    try:

        conexion = sqlite3.connect('configuracion.db')
        
        cursor = conexion.cursor()

        cursor.execute("DELETE FROM datos")

        cursor.execute(f"INSERT INTO datos VALUES ('{api_key}', '{ruta}', {protegeme})")

        # Guardamos los cambios haciendo un commit
        conexion.commit()

        conexion.close()

        guardado = True

    except:
        
        conexion.close()
        
    finally:
       
        conexion.close()
    

    return guardado


#OBTENER CONFIGURACION
def getConfiguracion():
    

    try:

        conexion = sqlite3.connect('configuracion.db')
        
        cursor = conexion.cursor()

        cursor.execute("SELECT * FROM datos")

        datos = cursor.fetchone()

    except:
            
        conexion.close()

    finally:
        
        conexion.close()

      

    return datos


#GUARDAR EXTENSIONES
def guardar_extensiones(extensiones):
    

    try:
        
        conexion = sqlite3.connect('configuracion.db')
            
        cursor = conexion.cursor()

        #cursor.execute("CREATE TABLE extensiones (nombres_extensiones VARCHAR(10))")

        cursor.execute("DELETE FROM extensiones")

        cursor.execute("INSERT INTO extensiones VALUES ('"+ extensiones +"')")

        conexion.commit()

        conexion.close()
    
    except:
        
        conexion.close()
        
    finally:
       
        conexion.close()

    
#OBTENER EXTENSIONES
def getExtensiones():
    
    try:

        conexion = sqlite3.connect('configuracion.db')
        
        cursor = conexion.cursor()

        cursor.execute("SELECT * FROM extensiones")

        extensiones = cursor.fetchone()
    
        
        

    except:
            
        conexion.close()

    finally:
        
        conexion.close()

      
    
    return extensiones
