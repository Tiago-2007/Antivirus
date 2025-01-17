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
from PIL import Image, ImageTk  # Biblioteca para manipular imagens

# Define o diretório de quarentena e logs
DIRETORIO_QUARENTENA = "quarentena"
DIRETORIO_LOG = "logs.txt"

# Função para calcular o hash SHA-256 de um arquivo
def calcular_hash(filepath):
    sha256 = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
    except Exception as e:
        print(f"Erro ao ler o arquivo {filepath}: {e}")
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

# Verifica se os diretórios de quarentena e logs existem
def verificar_diretorios():
    if not os.path.exists(DIRETORIO_QUARENTENA):
        os.makedirs(DIRETORIO_QUARENTENA)
    if not os.path.exists(DIRETORIO_LOG):
        with open(DIRETORIO_LOG, 'w') as log_file:
            log_file.write("Logs de Atividades:\n")

# Escaneia o arquivo especificado
def escanear_arquivo(filepath):
    hashes_maliciosos = carregar_hashes_maliciosos()
    file_hash = calcular_hash(filepath)

    if file_hash is None:
        messagebox.showerror("Erro", "Não foi possível calcular o hash do arquivo.")
        return

    if file_hash in hashes_maliciosos:
        mover_para_quarentena(filepath)
    else:
        if heuristica_possivel(filepath):
            mover_para_quarentena(filepath)
        else:
            mostrar_carinha_feliz("Nenhum arquivo infectado encontrado.")

# Move o arquivo para a quarentena
def mover_para_quarentena(filepath):
    verificar_diretorios()
    try:
        shutil.move(filepath, os.path.join(DIRETORIO_QUARENTENA, os.path.basename(filepath)))
        log_atividade(f"Arquivo infectado encontrado e movido para quarentena: {filepath}")
        messagebox.showwarning("ALERTA", f"Arquivo infectado encontrado e movido para quarentena: {filepath}")
        atualizar_lista_quarentena()
    except Exception as e:
        messagebox.showerror("Erro", f"Não foi possível mover o arquivo para a quarentena: {e}")

# Função de detecção heurística (exemplo simples)
def heuristica_possivel(filepath):
    if filepath.endswith(('.exe', '.bat', '.cmd')) and os.path.getsize(filepath) > 1e6:
        log_atividade(f"Detecção heurística: arquivo suspeito encontrado: {filepath}")
        return True
    return False

# Log de atividades
def log_atividade(mensagem):
    with open(DIRETORIO_LOG, 'a') as log_file:
        log_file.write(mensagem + "\n")

# Escolher um arquivo para escanear
def escolher_arquivo():
    filepath = filedialog.askopenfilename(title="Escolha um arquivo para escanear")
    if filepath:
        escanear_arquivo(filepath)

# Remover arquivos da quarentena
def remover_da_quarentena():
    selected_file = listbox_quarentena.get(tk.ACTIVE)
    if not selected_file:
        messagebox.showinfo("Quarentena", "Nenhum arquivo selecionado.")
        return
    filepath = os.path.join(DIRETORIO_QUARENTENA, selected_file)
    os.remove(filepath)
    log_atividade(f"Arquivo removido da quarentena: {selected_file}")
    messagebox.showinfo("Remoção", f"Arquivo removido: {selected_file}")
    atualizar_lista_quarentena()

# Atualiza a lista de arquivos na quarentena
def atualizar_lista_quarentena():
    files = os.listdir(DIRETORIO_QUARENTENA)
    listbox_quarentena.delete(0, tk.END)
    for file in files:
        listbox_quarentena.insert(tk.END, file)

# Mostra uma carinha feliz em uma janela separada
def mostrar_carinha_feliz(mensagem):
    janela_feliz = tk.Toplevel()
    janela_feliz.title("Nenhuma Ameaça Encontrada")
    janela_feliz.geometry("300x300")

    # Carrega a imagem
    try:
        imagem = Image.open("feliz.png")
        imagem = imagem.resize((150, 150), Image.ANTIALIAS)  # Redimensiona a imagem
        img_tk = ImageTk.PhotoImage(imagem)
        label_imagem = tk.Label(janela_feliz, image=img_tk)
        label_imagem.image = img_tk  # Mantém uma referência para evitar garbage collection
        label_imagem.pack(pady=10)
    except Exception as e:
        tk.Label(janela_feliz, text="Imagem não encontrada!", font=("Helvetica", 12)).pack(pady=10)

    # Exibe a mensagem
    tk.Label(janela_feliz, text=mensagem, font=("Helvetica", 14)).pack(pady=10)

# Configuração da interface gráfica
def main():
    global listbox_quarentena

    verificar_diretorios()

    # Janela principal
    root = tk.Tk()
    root.title("Antivírus Simples")
    root.geometry("600x400")
    root.resizable(False, False)

    # Estilo
    style = ttk.Style()
    style.theme_use("clam")

    # Frame Superior
    frame_top = ttk.Frame(root, padding="10")
    frame_top.pack(fill=tk.X)

    ttk.Label(frame_top, text="Antivírus Simples", font=("Helvetica", 16)).pack()

    # Frame do Meio
    frame_middle = ttk.Frame(root, padding="10")
    frame_middle.pack(expand=True, fill=tk.BOTH)

    # Botões de ação
    btn_escolher = ttk.Button(frame_middle, text="Escolher Arquivo para Escanear", command=escolher_arquivo)
    btn_escolher.pack(pady=5)

    btn_remover = ttk.Button(frame_middle, text="Remover Arquivo da Quarentena", command=remover_da_quarentena)
    btn_remover.pack(pady=5)

    # Lista de quarentena
    ttk.Label(frame_middle, text="Arquivos em Quarentena:").pack()
    listbox_quarentena = tk.Listbox(frame_middle, height=10)
    listbox_quarentena.pack(expand=True, fill=tk.BOTH)

    # Rodapé
    frame_bottom = ttk.Frame(root, padding="10")
    frame_bottom.pack(fill=tk.X)

    ttk.Label(frame_bottom, text="Desenvolvido por Você", font=("Helvetica", 10)).pack()

    atualizar_lista_quarentena()

    root.mainloop()

if __name__ == "__main__":
    main()
