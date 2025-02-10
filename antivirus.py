"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""
    Programador............: Tiago Machado
    Data...................: 31/10/2024
    Observações............: Um antivirus que identifica se o ficheiro ta corrompido, se tem algum malware

"""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""""

import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import shutil
from tkinter import ttk
from PIL import Image, ImageTk
import threading
import time  # Importação da biblioteca time
import logging
from logging.handlers import RotatingFileHandler
import ctypes
import winreg

DIRETORIO_QUARENTENA = "quarentena"
DIRETORIO_LOG = "logs.txt"



# Configuração do logger com rotação de logs
def configurar_logger():
    logger = logging.getLogger()
    logger.setLevel(logging.INFO)
    
    # Criar o handler de rotação de logs (tamanho máximo de 1MB, mantendo 3 backups)
    handler = RotatingFileHandler(DIRETORIO_LOG, maxBytes=1e6, backupCount=3)
    handler.setFormatter(logging.Formatter('%(asctime)s - %(message)s'))
    logger.addHandler(handler)

# Função para calcular o hash SHA-256 de um ficheiro
def calcular_hash(caminho_ficheiro):
    sha256 = hashlib.sha256()
    try:
        with open(caminho_ficheiro, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
    except FileNotFoundError:
        print(f"Ficheiro não encontrado: {caminho_ficheiro}")
        return None
    except PermissionError:
        print(f"Sem permissão para aceder ao ficheiro: {caminho_ficheiro}")
        return None
    except Exception as e:
        print(f"Erro ao calcular hash do ficheiro {caminho_ficheiro}: {e}")
        return None
    return sha256.hexdigest()

# Carrega as assinaturas de malware (hashes conhecidos)
def carregar_hashes_maliciosos():
    try:
        with open("hashes_maliciosos.txt", "r") as file:
            return {line.strip() for line in file}
    except FileNotFoundError:
        
        return set()
    except Exception as e:
        print(f"Erro ao carregar hashes maliciosos: {e}")
        return set()

# Verifica se os diretórios de quarentena e logs existem
def verificar_diretorios():
    try:
        if not os.path.exists(DIRETORIO_QUARENTENA):
            os.makedirs(DIRETORIO_QUARENTENA)
        if not os.path.exists(DIRETORIO_LOG):
            with open(DIRETORIO_LOG, 'w') as log_file:
                log_file.write("Logs de Atividades:\n")
    except PermissionError:
        print("Erro: Sem permissão para criar diretórios necessários.")
    except Exception as e:
        print(f"Erro ao verificar/criar diretórios: {e}")

# Função para calcular o hash SHA-256 de um ficheiro
def calcular_hash(caminho_ficheiro):
    sha256 = hashlib.sha256()
    try:
        with open(caminho_ficheiro, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
    except FileNotFoundError:
        print(f"Ficheiro não encontrado: {caminho_ficheiro}")
        return None
    except PermissionError:
        print(f"Sem permissão para aceder ao ficheiro: {caminho_ficheiro}")
        return None
    except Exception as e:
        print(f"Erro ao calcular hash do ficheiro {caminho_ficheiro}: {e}")
        return None
    return sha256.hexdigest()

# Testar a função de hash no arquivo EICAR
def calcular_hash_eicar():
    eicar_file = filedialog.askopenfilename(title="Escolha o arquivo EICAR")  # Seleciona o arquivo EICAR
    if eicar_file:
        eicar_hash = calcular_hash(eicar_file)
        print("SHA-256 do arquivo EICAR:", eicar_hash)
    else:
        print("Nenhum arquivo EICAR selecionado.")



# Escaneia os ficheiros especificados
def scanear_ficheiros(caminhos_ficheiros):
    if not caminhos_ficheiros:
        messagebox.showerror("Erro", "Nenhum ficheiro selecionado.")
        return

    hashes_maliciosos = carregar_hashes_maliciosos()

    for caminho_ficheiro in caminhos_ficheiros:
        if not os.path.isfile(caminho_ficheiro):
            messagebox.showerror("Erro", f"O caminho especificado não é um ficheiro válido: {caminho_ficheiro}")
            continue

        hash_ficheiro = calcular_hash(caminho_ficheiro)

        if hash_ficheiro is None:
            messagebox.showerror("Erro", f"Não foi possível calcular o hash do ficheiro: {caminho_ficheiro}")
            continue

        if hash_ficheiro in hashes_maliciosos:
            mover_para_quarentena(caminho_ficheiro)
            mostrar_carinha_triste("Ameaça encontrada!!!")  # Quando detectar ameaça
        else:
            if heuristica_possivel(caminho_ficheiro):
                mover_para_quarentena(caminho_ficheiro)
                mostrar_carinha_triste("Ameaça encontrada!!!")  # Quando heurística encontrar algo suspeito
            else:
                mostrar_carinha_feliz(f"Nenhuma ameaça encontrada")

# Move o ficheiro para a quarentena
def mover_para_quarentena(caminho_ficheiro):
    verificar_diretorios()
    try:
        destino = os.path.join(DIRETORIO_QUARENTENA, os.path.basename(caminho_ficheiro))
        if os.path.exists(destino):
            raise FileExistsError("O ficheiro já existe na quarentena.")
        shutil.move(caminho_ficheiro, destino)
        atualizar_lista_quarentena()
    except FileNotFoundError:
        messagebox.showerror("Erro", "Ficheiro não encontrado para mover para a quarentena.")
    except PermissionError:
        messagebox.showerror("Erro", "Sem permissão para mover o ficheiro para a quarentena.")
    except FileExistsError as e:
        messagebox.showerror("Erro", str(e))
    except Exception as e:
        messagebox.showerror("Erro", f"Não foi possível mover o ficheiro para a quarentena: {e}")

# Função de detecção heurística (exemplo simples)
def heuristica_possivel(caminho_ficheiro):
    try:
        if caminho_ficheiro.endswith(('.exe', '.bat', '.cmd', '.com')) and os.path.getsize(caminho_ficheiro) > 1e6:
            log_atividade(f"Detecção heurística: ficheiro suspeito encontrado: {caminho_ficheiro}")
            return True

        # Verificação se o ficheiro foi modificado nas últimas 24 horas
        tempo_modificacao = os.path.getmtime(caminho_ficheiro)
        if tempo_modificacao > (time.time() - 60 * 60 * 24):  # Modificado nas últimas 24 horas
            log_atividade(f"Ficheiro modificado recentemente e suspeito: {caminho_ficheiro}")
            return True
    except FileNotFoundError:
        print(f"Ficheiro não encontrado para análise heurística: {caminho_ficheiro}")
    except Exception as e:
        print(f"Erro na análise heurística para {caminho_ficheiro}: {e}")
    return False

# Log de atividades com rotação
def log_atividade(mensagem):
    logging.info(mensagem)

# Escolher múltiplos ficheiros para scanear
def escolher_ficheiros():
    caminhos_ficheiros = filedialog.askopenfilenames(title="Escolha os ficheiros para scanear")
    if caminhos_ficheiros:
        scanear_ficheiros(caminhos_ficheiros)

# Remover ficheiros da quarentena
def remover_da_quarentena():
    ficheiro_selecionado = listbox_quarentena.get(tk.ACTIVE)
    if not ficheiro_selecionado:
        messagebox.showinfo("Quarentena", "Nenhum ficheiro em querentena.")
        return
    caminho_ficheiro = os.path.join(DIRETORIO_QUARENTENA, ficheiro_selecionado)
    try:
        os.remove(caminho_ficheiro)
        log_atividade(f"Ficheiro removido da quarentena: {ficheiro_selecionado}")
        messagebox.showinfo("Remoção", f"Ficheiro removido: {ficheiro_selecionado}")
        atualizar_lista_quarentena()
    except FileNotFoundError:
        messagebox.showerror("Erro", "Ficheiro não encontrado na quarentena.")
    except PermissionError:
        messagebox.showerror("Erro", "Sem permissão para remover o ficheiro da quarentena.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao remover o ficheiro: {e}")

# Atualiza a lista de ficheiros na quarentena
def atualizar_lista_quarentena():
    try:
        ficheiros = os.listdir(DIRETORIO_QUARENTENA)
        listbox_quarentena.delete(0, tk.END)
        for ficheiro in ficheiros:
            listbox_quarentena.insert(tk.END, ficheiro)
    except FileNotFoundError:
        print("Diretório de quarentena não encontrado.")

    threading.Timer(1, atualizar_lista_quarentena).start()  # Chama novamente em 1 segundo

# Mostra uma carinha feliz em uma janela separada
janela_feliz_instancia = None  # Variável global para controlar a instância da janela

def mostrar_carinha_feliz(mensagem):
    global janela_feliz_instancia

    if janela_feliz_instancia and janela_feliz_instancia.winfo_exists():  # Verifica se já existe
        janela_feliz_instancia.lift()  # Traz a janela existente para a frente
        return

    janela_feliz_instancia = tk.Toplevel()
    janela_feliz_instancia.title("Nenhuma Ameaça Encontrada")
    janela_feliz_instancia.geometry("300x300")

    try:
        imagem = Image.open("feliz.png")
        imagem = imagem.resize((150, 150), Image.LANCZOS)
        img_tk = ImageTk.PhotoImage(imagem)
        label_imagem = tk.Label(janela_feliz_instancia, image=img_tk)
        label_imagem.image = img_tk
        label_imagem.pack(pady=10)
    except FileNotFoundError:
        tk.Label(janela_feliz_instancia, text="Imagem não encontrada!", font=("Helvetica", 12)).pack(pady=10)
    except Exception as e:
        tk.Label(janela_feliz_instancia, text=f"Erro ao carregar imagem: {e}", font=("Helvetica", 12)).pack(pady=10)

    tk.Label(janela_feliz_instancia, text=mensagem, font=("Helvetica", 14)).pack(pady=10)

    # Fecha a janela ao clicar em "OK"
    btn_ok = ttk.Button(janela_feliz_instancia, text="OK", command=janela_feliz_instancia.destroy)
    btn_ok.pack(pady=10)

# Mostra uma carinha triste em uma janela separada
janela_triste_instancia = None  # Variável global para controlar a instância da janela

def mostrar_carinha_triste(mensagem):
    global janela_triste_instancia

    if janela_triste_instancia and janela_triste_instancia.winfo_exists():  # Verifica se já existe
        janela_triste_instancia.lift()  # Traz a janela existente para a frente
        return

    janela_triste_instancia = tk.Toplevel()
    janela_triste_instancia.title("Ameaça Encontrada!!!")
    janela_triste_instancia.geometry("300x300")

    try:
        imagem = Image.open("triste.png")  # A imagem "triste.png" deve estar no mesmo diretório
        imagem = imagem.resize((150, 150), Image.LANCZOS)
        img_tk = ImageTk.PhotoImage(imagem)
        label_imagem = tk.Label(janela_triste_instancia, image=img_tk)
        label_imagem.image = img_tk
        label_imagem.pack(pady=10)
    except FileNotFoundError:
        tk.Label(janela_triste_instancia, text="Imagem não encontrada!", font=("Helvetica", 12)).pack(pady=10)
    except Exception as e:
        tk.Label(janela_triste_instancia, text=f"Erro ao carregar imagem: {e}", font=("Helvetica", 12)).pack(pady=10)

    tk.Label(janela_triste_instancia, text=mensagem, font=("Helvetica", 14)).pack(pady=10)

    # Fecha a janela ao clicar em "OK"
    btn_ok = ttk.Button(janela_triste_instancia, text="OK", command=janela_triste_instancia.destroy)
    btn_ok.pack(pady=10)
    
def verificar_modo_escuro():
    """Verifica se o Windows está no modo escuro"""
    try:
        # Acessa o registro do Windows
        chave = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize")
        valor, _ = winreg.QueryValueEx(chave, "AppsUseLightTheme")
        winreg.CloseKey(chave)
        return valor == 0  # 0 = Modo escuro, 1 = Modo claro
    except Exception as e:
        print(f"Erro ao verificar tema do Windows: {e}")
        return False  # Padrão para claro se falhar
def atualizar_tema(root):
    """Aplica o tema com base no modo do Windows"""
    if verificar_modo_escuro():
        root.configure(bg="black")
        style.configure("TFrame", background="black")
        style.configure("TLabel", background="black", foreground="white")
        style.configure("TButton", background="gray", foreground="white")
        listbox_quarentena.configure(bg="black", fg="white")
    else:
        root.configure(bg="white")
        style.configure("TFrame", background="white")
        style.configure("TLabel", background="white", foreground="black")
        style.configure("TButton", background="lightgray", foreground="black")
        listbox_quarentena.configure(bg="white", fg="black")

    # Atualiza a cada 10 segundos para verificar mudanças no tema
    root.after(10000, lambda: atualizar_tema(root))

# Configuração da interface gráfica
def main():
    global listbox_quarentena, style

    configurar_logger()
    verificar_diretorios()
    
    root = tk.Tk()
    root.title("ThreatDetect")
    root.resizable(True, True)

    style = ttk.Style()
    style.theme_use("clam")

    frame_top = ttk.Frame(root, padding="10")
    frame_top.pack(fill=tk.X)

    ttk.Label(frame_top, text="ThreatDetect", font=("Helvetica", 16)).pack()

    frame_middle = ttk.Frame(root, padding="10")
    frame_middle.pack(expand=True, fill=tk.BOTH)

    btn_escolher = ttk.Button(frame_middle, text="Escolher Ficheiros para scanear", command=escolher_ficheiros)
    btn_escolher.pack(pady=5, fill=tk.X)

    btn_remover = ttk.Button(frame_middle, text="Remover Ficheiro da Quarentena", command=remover_da_quarentena)
    btn_remover.pack(pady=5, fill=tk.X)

    ttk.Label(frame_middle, text="Ficheiros em Quarentena:").pack()
    listbox_quarentena = tk.Listbox(frame_middle, height=10)
    listbox_quarentena.pack(expand=True, fill=tk.BOTH)

    frame_bottom = ttk.Frame(root, padding="10")
    frame_bottom.pack(fill=tk.X)
    
    atualizar_lista_quarentena()
    atualizar_tema(root)  # Aplica o tema no início e agenda verificações

    root.mainloop()

if __name__ == "__main__":
    main()
