"""
Programador............: Tiago Machado
Data...................: 31/10/2024
Observações............: Um antivirus que identifica se o ficheiro ta corrompido, se tem algum malware
"""

import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import shutil
from tkinter import ttk
from PIL import Image, ImageTk
import time  # Importação da biblioteca time
import logging
from logging.handlers import RotatingFileHandler

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

# Função para calcular o hash SHA-256 de um arquivo
def calcular_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
    except FileNotFoundError:
        print(f"Arquivo não encontrado: {filepath}")
        return None
    except PermissionError:
        print(f"Sem permissão para acessar o arquivo: {filepath}")
        return None
    except Exception as e:
        print(f"Erro ao calcular hash do arquivo {filepath}: {e}")
        return None
    return sha256.hexdigest()

# Carrega as assinaturas de malware (hashes conhecidos)
def carregar_hashes_maliciosos():
    try:
        with open("hashes_maliciosos.txt", "r") as file:
            return {line.strip() for line in file}
    except FileNotFoundError:
        mostrar_carinha_feliz("Nenhuma ameaça encontrada.")
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

# Escaneia os arquivos especificados
def escanear_arquivos(filepaths):
    if not filepaths:
        messagebox.showerror("Erro", "Nenhum arquivo selecionado.")
        return

    hashes_maliciosos = carregar_hashes_maliciosos()

    for filepath in filepaths:
        if not os.path.isfile(filepath):
            messagebox.showerror("Erro", f"O caminho especificado não é um arquivo válido: {filepath}")
            continue

        file_hash = calcular_hash(filepath)

        if file_hash is None:
            messagebox.showerror("Erro", f"Não foi possível calcular o hash do arquivo: {filepath}")
            continue

        if file_hash in hashes_maliciosos:
            mover_para_quarentena(filepath)
        else:
            if heuristica_possivel(filepath):
                mover_para_quarentena(filepath)
            else:
                mostrar_carinha_feliz(f"Nenhum arquivo infectado encontrado: {filepath}")

# Move o arquivo para a quarentena
def mover_para_quarentena(filepath):
    verificar_diretorios()
    try:
        destino = os.path.join(DIRETORIO_QUARENTENA, os.path.basename(filepath))
        if os.path.exists(destino):
            raise FileExistsError("O arquivo já existe na quarentena.")
        shutil.move(filepath, destino)
        log_atividade(f"Arquivo infectado encontrado e movido para quarentena: {filepath}")
        messagebox.showwarning("ALERTA", f"Arquivo infectado encontrado e movido para quarentena: {filepath}")
        atualizar_lista_quarentena()
    except FileNotFoundError:
        messagebox.showerror("Erro", "Arquivo não encontrado para mover para a quarentena.")
    except PermissionError:
        messagebox.showerror("Erro", "Sem permissão para mover o arquivo para a quarentena.")
    except FileExistsError as e:
        messagebox.showerror("Erro", str(e))
    except Exception as e:
        messagebox.showerror("Erro", f"Não foi possível mover o arquivo para a quarentena: {e}")

# Função de detecção heurística (exemplo simples)
def heuristica_possivel(filepath):
    try:
        if filepath.endswith(('.exe', '.bat', '.cmd')) and os.path.getsize(filepath) > 1e6:
            log_atividade(f"Detecção heurística: arquivo suspeito encontrado: {filepath}")
            return True

        # Verificação se o arquivo foi modificado nas últimas 24 horas
        tempo_modificacao = os.path.getmtime(filepath)
        if tempo_modificacao > (time.time() - 60 * 60 * 24):  # Modificado nas últimas 24 horas
            log_atividade(f"Arquivo modificado recentemente e suspeito: {filepath}")
            return True
    except FileNotFoundError:
        print(f"Arquivo não encontrado para análise heurística: {filepath}")
    except Exception as e:
        print(f"Erro na análise heurística para {filepath}: {e}")
    return False

# Log de atividades com rotação
def log_atividade(mensagem):
    logging.info(mensagem)

# Escolher múltiplos arquivos para escanear
def escolher_arquivos():
    filepaths = filedialog.askopenfilenames(title="Escolha os arquivos para escanear")
    if filepaths:
        escanear_arquivos(filepaths)

# Remover arquivos da quarentena
def remover_da_quarentena():
    selected_file = listbox_quarentena.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showinfo("Quarentena", "Nenhum arquivo selecionado.")
        return
    filepath = os.path.join(DIRETORIO_QUARENTENA, selected_file)
    try:
        os.remove(filepath)
        log_atividade(f"Arquivo removido da quarentena: {selected_file}")
        messagebox.showinfo("Remoção", f"Arquivo removido: {selected_file}")
        atualizar_lista_quarentena()
    except FileNotFoundError:
        messagebox.showerror("Erro", "Arquivo não encontrado na quarentena.")
    except PermissionError:
        messagebox.showerror("Erro", "Sem permissão para remover o arquivo da quarentena.")
    except Exception as e:
        messagebox.showerror("Erro", f"Erro ao remover o arquivo: {e}")

# Atualiza a lista de arquivos na quarentena
def atualizar_lista_quarentena():
    try:
        files = os.listdir(DIRETORIO_QUARENTENA)
        listbox_quarentena.delete(0, tk.END)
        for file in files:
            listbox_quarentena.insert(tk.END, file)
    except FileNotFoundError:
        print("Diretório de quarentena não encontrado.")
    except Exception as e:
        print(f"Erro ao atualizar a lista de quarentena: {e}")

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

# Configuração da interface gráfica
def main():
    global listbox_quarentena

    configurar_logger()  # Chama a função para configurar o logger

    verificar_diretorios()

    root = tk.Tk()
    root.title("Antivírus Simples")
    root.resizable(True, True)  # Agora a janela pode ser redimensionada

    style = ttk.Style()
    style.theme_use("clam")

    frame_top = ttk.Frame(root, padding="10")
    frame_top.pack(fill=tk.X)

    ttk.Label(frame_top, text="Antivírus Simples", font=("Helvetica", 16)).pack()

    frame_middle = ttk.Frame(root, padding="10")
    frame_middle.pack(expand=True, fill=tk.BOTH)

    btn_escolher = ttk.Button(frame_middle, text="Escolher Arquivos para Escanear", command=escolher_arquivos)
    btn_escolher.pack(pady=5, fill=tk.X)

    btn_remover = ttk.Button(frame_middle, text="Remover Arquivo da Quarentena", command=remover_da_quarentena)
    btn_remover.pack(pady=5, fill=tk.X)

    ttk.Label(frame_middle, text="Arquivos em Quarentena:").pack()
    listbox_quarentena = tk.Listbox(frame_middle, height=10)
    listbox_quarentena.pack(expand=True, fill=tk.BOTH)

    frame_bottom = ttk.Frame(root, padding="10")
    frame_bottom.pack(fill=tk.X)
    
    atualizar_lista_quarentena()

    root.mainloop()

if __name__ == "__main__":
    main()