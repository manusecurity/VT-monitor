from tkinter import *
from tkinter import ttk
from tkinter import scrolledtext
from tkinter import messagebox
from tkinter import filedialog
import tkinter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from threading import Thread
import funcionVirusTotal
import comprobaciones
import ntpath
import time
import sys
import configuracion
import os
import re


#VARIABLES GLOBALES PARA EL PROGRAMA
ARCHIVOS_EN_COLA = list()
API_KEY = ""
RUTA = ""
RUTAS = ""
EXTENSIONES = ""
PROTECCION = 0


stext = scrolledtext
observer = Observer()


#CLASE PARA LA MONITORIZACION DE EVENTOS EN EL SISTEMA DE ARCHIVOS
class MyEventHandler(FileSystemEventHandler):


    #LLAMADAS A LAS FUNCIONES DE MONITORIZACION
    def on_created(self, event):     
        proceder_con_la_ruta(event)



#QUE HACER EN LA RUTA MONITORIZADA
def proceder_con_la_ruta(event):
    comprobar_conexion = comprobaciones.comprobar_conexion()
    #SI HAY CONEXION CON VIRUSTOTAL PROCEDE
           
        
    global RUTAS
    global ARCHIVOS_EN_COLA
    rutaactual = ""   
    rutaactual = (event.src_path)
    ARCHIVOS_EN_COLA.append(rutaactual)
    RUTAS = ARCHIVOS_EN_COLA[0]
        
        
    nombre_archivo = ntpath.basename(rutaactual)
    extension = os.path.splitext(nombre_archivo)
    ruta_sin_extension = os.path.splitext(rutaactual)
    
    extensiones_a_monitorizar = configuracion.getExtensiones()
        
    if str(extension[1]) in str(extensiones_a_monitorizar[0]):
            

        #EL TAMAÑO DEL FICHERO NO PUEDE PASAR DE 32 MB
        tamaño_archivo = os.path.getsize(rutaactual)
        if int(tamaño_archivo) < 33554432:

            hora = time.strftime('%H:%M:%S', time.localtime())
            
            stext.insert(END, str(hora) + "-Analizando el archivo: " + nombre_archivo + ". Espere por favor.. \n") 
            
            ArchivoAnalizar = ""
            if PROTECCION == 0:
                ArchivoAnalizar = rutaactual
            elif PROTECCION == 1:
                try:
                    os.rename(rutaactual, ruta_sin_extension[0] + ".BLOQUEADO")
                    ArchivoAnalizar = ruta_sin_extension[0] + ".BLOQUEADO"
                except:
                    messagebox.ERROR("Error al modificar la extensión en el archivo, si ha quedado modificado puede cambiarlo manualmente haciendo CLICK con el botón derecho en el archivo y CAMBIAR NOMBRE")

            
            
            try:
                    
                resultado = funcionVirusTotal.analiza(API_KEY, ArchivoAnalizar)
            
                    
                ARCHIVOS_EN_COLA.remove(rutaactual)
            except:
                pass
            
            
            
            if resultado[0] != -1:
                hora = time.strftime('%H:%M:%S', time.localtime())
                if(resultado[0] > 0):
                    stext.insert(END, str(hora) + "-Resultado del archivo analizado " + nombre_archivo + ": " + str(resultado[0]) + " AMENAZAS. \n", 'amenaza')        
                    renombrar_archivos(rutaactual, ruta_sin_extension[0], "VIRUS") 
                elif(resultado[0] == 0):
                    stext.insert(END, str(hora) + "-Resultado del archivo analizado " + nombre_archivo + ": " + str(resultado[0]) + " amenazas. \n", 'sin_amenazas')
                    renombrar_archivos(rutaactual, ruta_sin_extension[0], "LIBERADO") 
               
                stext.tag_config('amenaza', background='red')
                stext.tag_config('sin_amenazas', background='green')
                

            else:
                #SI NO HAY CONEXION CON VIRUSTOTAL RE RENOMBRA EL ARCHIVO A SU ESTADO ORIGINAL
                renombrar_archivos(rutaactual, ruta_sin_extension[0], "LIBERADO")
                stext.insert(END, str(hora) + "-Se ha encontrado el archivo " + nombre_archivo + ": " + "No se ha podido analizar por que no hay conexión \n", 'sin_conexion')
                stext.tag_config('sin_conexion', background='orange')
        
        else:
            hora = time.strftime('%H:%M:%S', time.localtime())
            
            stext.insert(END, str(hora) + "-Se ha encontrado el archivo: " + nombre_archivo + " pero no se puede analizar ya que excede 32 MB \n", 'no_escaneado') 
            stext.tag_config('no_escaneado', background='orange')
            ArchivoAnalizar = ""
            ARCHIVOS_EN_COLA.remove(rutaactual)

                               
        
#RENOMBRAR EXTENSIONES POR BLOQUEADO PARA EL PROCESO DE ESCANEADO O VIRUS CUANDO EXISTA INFECCION
def renombrar_archivos(rutaactual, ruta_sin_extension, operacion):
        try:
            
            if PROTECCION == 1:
                
                if operacion == "VIRUS":
                    nuevonombre = ruta_sin_extension + ".VIRUS"
                    os.rename(ruta_sin_extension + ".BLOQUEADO", nuevonombre)
                
                elif operacion == "BLOQUEADO":
                    nuevonombre = ruta_sin_extension + ".BLOQUEADO"
                    os.rename(rutaactual, nuevonombre)

                elif operacion == "LIBERADO":
                    os.rename(ruta_sin_extension + ".BLOQUEADO", rutaactual)
                
                else:
                    pass
            
        except:
            messagebox.ERROR("Error al modificar la extensión en el archivo, si ha quedado modificado puede cambiarlo manualmente haciendo CLICK con el botón derecho en el archivo y CAMBIAR NOMBRE")

  
    
#DEFINICION DEL OBSERVER Y EL HILO A EJECUTAR
def wachdog():

    global observer
    observer.schedule(MyEventHandler(), RUTA, recursive=False)
    observer.start()

    
    try:
        while observer.is_alive():
            observer.join(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()



    
#FUNCION PARA CREAR LA GUI
def tkgui():

    window = Tk()
    window.title("VT MONITOR")
    window.geometry('800x600')
    window.resizable(0,0)

    frameSup = Frame(window)
    frameSup.grid(column=0, row=0, sticky="w")

    frameInf = Frame(window)
    frameInf.grid(column=0, row=4, sticky="w")


    lbl = Label(frameSup, text="RUTA DE DESCARGAS:")
    lbl.grid(column=0, row=0, sticky="w")

    ruta_var = StringVar(window, value=RUTA)
    campoRuta = Entry(frameSup,width=70, textvariable=ruta_var)
    campoRuta.grid(column=1, row=0, sticky="w")

    lbl = Label(frameSup, text="    ")
    lbl.grid(column=2, row=4, sticky='w')

    
    def buscar_ruta():
        global RUTA
        RUTA = filedialog.askdirectory(initialdir=".", title="Seleccione directorio a monitorizar")

        campoRuta.delete(0, END)
        campoRuta.insert(0, RUTA)


    
    #BOTON PARA BUSCAR LA RUTA DEL DIRECTORIO A MONITORIZAR
    BotonBuscarRuta = Button(frameSup, text="Explorar", command = lambda: buscar_ruta())
    BotonBuscarRuta.grid(column=3, row=0, sticky="w")


    lbl = Label(frameSup, text=" ")
    lbl.grid(column=0, row=5, sticky="w")

    lbl = Label(frameSup, text="VIRUS TOTAL API KEY:")
    lbl.grid(column=0, row=4, sticky='w')

    
    lbl = Label(frameSup, text="EXTENSIONES:")
    lbl.grid(column=0, row=5, sticky="w")

    valor_extensiones = str(EXTENSIONES)
    valor_extensiones = re.sub("\{|\'|\}","",valor_extensiones)
    valor_extensiones = re.sub("\(|\'|\)","",valor_extensiones)
    valor_extensiones = re.sub("\,,|\'|\,,,","",valor_extensiones)
    
    extensiones_var = StringVar(window, value=valor_extensiones)
    campoExtensiones = Entry(frameSup,width=70, textvariable=extensiones_var)
    campoExtensiones.grid(column=1, row=5, sticky="w")


    key_var = StringVar(window, value=API_KEY)
    campoKey = Entry(frameSup,width=70, textvariable=key_var)
    campoKey.grid(column=1, row=4, sticky="w")

    lbl = Label(frameSup, text="    ")
    lbl.grid(column=2, row=0, sticky='w')


    key_var=StringVar()
    ruta_var=StringVar()
    
   
   
    #BOTON DE GUARDAR CONFIGURACION
    def submit():
 
        key_string=campoKey.get()
        ruta_string=campoRuta.get()
        extensiones_string = campoExtensiones.get()
        global PROTECCION

        if key_string == "" or ruta_string == "" or extensiones_string=="":
            messagebox.showerror(message="Debe de proporcionar una API KEY, una ruta y unas extensiones a monitorizar.", title="Error")

        else:
            configuracion.guardarConfiguracion(key_string, ruta_string, PROTECCION)
            extension_limpia = re.sub("\{|\'|\}","",extensiones_string)
            configuracion.guardar_extensiones(extension_limpia)
            global API_KEY
            global RUTA
            global EXTENSIONES
            
            API_KEY = key_string
            RUTA = ruta_string
            EXTENSIONES = extensiones_string


            messagebox.showinfo(message="Guardado.", title="Info")


    BotonGuardar = Button(frameSup, text="Guardar", command=lambda: submit())
    BotonGuardar.grid(column=3, row=4, sticky="w")



    lbl = Label(frameSup, text= " ")
    lbl.grid(column=4, row=0, sticky="w")


    #CHECKBOX PARA LA FUNCIONALIDAD DE PROTEGEME
    cb = IntVar()

    def isChecked():
        global PROTECCION
        
        if cb.get() == 1:
            PROTECCION = 1
            
        elif cb.get() == 0:
           PROTECCION = 0
        
        
           
    
    CheckProtegeme = Checkbutton(frameSup, text="Protégeme", variable=cb, onvalue=1, offvalue=0, command=isChecked)
    CheckProtegeme.grid(column=5, row=0, sticky="w")
    
    if PROTECCION == 1:
        CheckProtegeme.select()
    elif PROTECCION == 0:
        CheckProtegeme.deselect()

    def ventanaAyuda():
        nuevaVentana = tkinter.Toplevel(window)
        nuevaVentana.title("Ayuda, créditos")
        nuevaVentana.geometry('630x400')
        nuevaVentana.resizable(0,0)

        campoInformacion = scrolledtext.ScrolledText(nuevaVentana,width=95,height=30)
        campoInformacion.grid(column=0, row=0)


        campoInformacion.insert("1.0","VT Monitor, creado por maxssestepa@gmail.com \n\nEste programa es capaz de monitorizar una carpeta a seleccionar\ncomo puede ser carpetas compartidas por varios usuarios o carpetas\ntipo Downloads y detectará los archivos nuevos en busca de malware.\nEste programa es capaz de analizar dichos ficheros con hasta 55 antivirus\ndiferentes. Tan solo hay que ingresar su API KEY, seleccionar la carpeta \na monitorizar y poner las extensiones de los archivos a monitorizar \nseparadas con comas.\nEl programa monitorizará archivos de hasta 32 MB y podrá protegerte en\ncaso de detectar archivos con malware renombrandolos con la extensión .VIRUS\n\nNOTA LEGAL\nEste programa no podrá ser sustituto de ningun programa antimalware.\nEl autor no se responsabiliza por el funcionamiento del programa,\nresultados de los análisis o usos del programa por parte del usuario.\nEl autor del programa no tiene ningun vinculo con VirusTotal®.\nAl usar este programa, aceptas los términos del servicio y la política de \nprivacidad de VirusTotal®.")
               

    BotonAyuda = Button(frameSup, text="Ayuda y créditos", command=lambda: ventanaAyuda())
    BotonAyuda.grid(column=5, row=4, sticky="w")
        
    
    global stext
    stext = scrolledtext.ScrolledText(frameInf,width=95,height=30)
    stext.grid(column=0, row=6)

    window.protocol("WM_DELETE_WINDOW", lambda: cerrar_ventana())


    #ARRANCAMOS LA GUI
    window.mainloop ()



def cerrar_ventana():
     if messagebox.askokcancel("Salir", "¿Seguro que desea salir"):
        observer.stop()
        sys.exit()


def obtener_configuracion():
    
    valores = configuracion.getConfiguracion()
   
    global API_KEY
    global RUTA
    global PROTECCION
    global EXTENSIONES
    
    try:
        API_KEY = valores[0]
        RUTA = valores[1]
        PROTECCION = valores[2]
        
        lista_extensiones = configuracion.getExtensiones()
        
        EXTENSIONES = lista_extensiones
             
        
    except:
        API_KEY = ""
        RUTA = "."
        PROTECCION = 0



def buscar_ruta():
    global RUTA
    RUTA = filedialog.askdirectory(initialdir=".", title="Seleccione directorio a monitorizar")
     

obtener_configuracion()

#EJECUCION DE LOS HILOS PARA LA CREACION DE LA GUI Y DE Wachdlog
hiloTkgui = Thread(target=tkgui)
hiloTkgui.start()   

    
hiloWachdog = Thread(target=wachdog)
hiloWachdog.start()