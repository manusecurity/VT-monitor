import sqlite3

conexion = sqlite3.connect('configuracion.db')

# Creamos el cursor
cursor = conexion.cursor()

# Ahora crearemos una tabla de usuarios con nombres, edades y emails
cursor.execute("CREATE TABLE datos (api_key VARCHAR(100), ruta VARCHAR(100), proteccion BOOLEAN NOT NULL CHECK (proteccion IN (0,1)))")


# Guardamos los cambios haciendo un commit
conexion.commit()

conexion.close()
      
      