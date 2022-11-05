#!/usr/bin/env python3


# imports
import os
import webbrowser
import string
import sys
import uuid
import cryptocode
import pickle
import ast
import time
from random import sample
from os import path
from virus_total_apis import PublicApi as VirusTotalPublicApi
import json
import hashlib
import random
import base64
import socket
import gzip
import glob
import sqlite3
import zipfile
import requests
from collections import defaultdict
from re import M
import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from tkinter import *
from tkinter import filedialog
from random import randint
from random import seed
from tkinter import filedialog as fd
from tkinter import ttk
from tkinter import *
from tkinter.colorchooser import *

# prep for self healing
with open(__file__, "r") as f:
  global antivirus_code
  antivirus_code = f.readlines()

# vars
virus = []
viruspath = []

# get home folder
home = os.path.expanduser('~')


def notify(title, text):
  os.system("""
							osascript -e 'display notification "{}" with title "{}"'
							""".format(text, title))
 
api_key = cryptocode.decrypt("QtC28a3Z5AX/wiaTCvS/BYkbDEg8cjKUOXCeD3yVDyAYa+LO1ym0pAOcMX0pC7T+0RxE89AVJOjhgMshkdLznQ==*J7THxK4B39HE1ykzY7XKGQ==*NAhkZa27taMXHEqhExU+Iw==*EE489s+HVzF87A8K9MgV1Q==", "       ") # Insert API Key here
vt = VirusTotalPublicApi(api_key)


class SizeTooLargeException(Exception):
    def __init__(self):
        pass

def upload_to_vt(file):
    with open(file, "rb") as f:
        malware_md5 = hashlib.md5(f.read()).hexdigest()
        response = vt.get_file_report(malware_md5)
        rsp_code = (response['results'])['response_code']
        if rsp_code == 0:
            if path.getsize(file) > 32000000:
                raise SizeTooLargeException("File size has exceeded maximum 32MB")
            else:
                file_response = vt.scan_file(f, from_disk=False)
                rsp_type = "file"
                return file_response, rsp_type
        else:
            rsp_type = "lookup"
            return response, rsp_type

def get_names(scans_dict):
    names = []
    for scans in scans_dict.keys():
        vals = scans_dict[scans]
        if vals['detected'] is True:
            names.append(vals['result'])
    return sample(names, min(5, len(names)))
def display(rsp_dict, rsp_type):
    results = rsp_dict['results']
    if rsp_type == 'file':
        return results['verbose_msg'], results['permalink']
    else:
        scans = results['scans']
        names = get_names(scans)
        return results

def virustotal(filename):
    rsp, rsp_type = upload_to_vt(filename)
    return display(rsp, rsp_type)

  
def save(data):
  data = "[{}]".format(data).encode()
  data = base64.b64encode(data)
  return gzip.compress(data)

def load(data):
  data = gzip.decompress(data)
  data = base64.b64decode(data)
  return ast.literal_eval(data.decode())[0]

def virustotal_scan(filename):
  if virustotal(filename)["scans"]["BitDefenderTheta"]["detected"] == False:
    return 0
  else:
    return 1


# database
settings_file = home + "/LTecher Antivirus Security/settings.dat"
vault_file = home + "/LTecher Antivirus Security/vault.dat"

try:
  os.mkdir(home + "/LTecher Antivirus Security")
except Exception:
  pass


def main():
  
  # functions
  def get_clean_caches_question():
    answer = load(open(settings_file, "rb").read())["ingore_list"][0]
    return answer

  def get_color():
    color = load(open(settings_file, "rb").read())["theme"][0]
    return color

  def get_checked_value():
    real_time = load(open(settings_file, "rb").read())["theme"][1]
    return real_time
  
  def get_ingore_values():
    return ast.literal_eval(load(open(settings_file, "rb").read())["ingore_list"][1])
  

  def exit():
    window.destroy()

  def check_permission(file, mode):
    try:
      open(file, mode)
      return True
    except PermissionError:
      return False

  def md5_hash(filename):
    with open(filename, "rb") as f:
      bytes = f.read()
      md5hash = hashlib.md5(bytes).hexdigest()
      f.close()

    return md5hash

  def malware_checker(pathOfFile):
    hash_malware_check = md5_hash(pathOfFile)

    malware_hashes = open("Database.txt", "r")
    malware_hashes_read = malware_hashes.read()
    malware_hashes.close()

    if malware_hashes_read.find(hash_malware_check) != -1:
      return 1
    else:
      return 0

  def scanfolder(path):
    dirlist = list()
    window.focus_force()
    deleting.config(text="Building directory map...")
    for (dirpath, dirnames, filename) in os.walk(path):
      dirlist += [os.path.join(dirpath, file) for file in filename]
      window.update()

    # find malware and space wasters
    files = get_ingore_values()
    filehashes = []
    for i in dirlist:
      try:
        if i not in files:
          window.update()
          deleting.config(text="Scanning: " + str(i))
          window.update()
          if malware_checker(i) != 0 or virustotal_scan(i) != 0:
            virus = []
            virus.append("Malware :: File :: " + i)  # the malware text on the screen
            viruses.insert(0, virus)  # put it in the list box
            viruspath.append(i)
            files.append(i)

        if get_clean_caches_question() == "yes":
          if i not in files and ".app" not in i:
            file_size = os.path.getsize(i)
            window.update()
            if file_size >= 200000000:
              viruses.insert(0, "{Huge file :: File :: " + i + "}")
              files.append(i)
    
            window.update()
    
          if i not in files:
            if i.endswith(".log") or i.endswith("log.txt") or i.endswith(".save") or i.endswith(
                    ".klg") or i.endswith(".session"):
              viruses.insert(0, "{Junk file :: File :: " + i + "}")
              files.append(i)
    
          if i not in files and list(i)[0] != ".":
            filehash = md5_hash(i)
            if filehash in filehashes:
              viruses.insert(0, "{Duplicate :: File :: " + i + "}") if ".localized" not in i else print("")
              files.append(i)
            else:
              filehashes.append(filehash)
      except:
        pass

  class auto_updates(socket.socket):
    def __init__(self):
      super().__init__(socket.AF_INET, socket.SOCK_STREAM)

      self.connect(("127.0.0.1", 55555))
      
    def message(self):
      while True:
        message = self.recv(1024).decode()

        if message == "UUID":
          self.send(hashlib.sha256(uuid.getnode()).hexdigest().encode())

      

  # engine
  class engine:
    def __init__(self):
      self.scan_type = None

    def quick(self):
      self.errors = 0
      self.scanlist = [f'{home}/Movies', f'{home}/Pictures', f'{home}/Downloads', f'{home}/Documents',
                       f'{home}/Desktop', f'{home}/Music']

      checkbox.place(x=100000000, y=10000000000000)
      wait.config(text="")
      window.unbind("<BackSpace>")
      scan.config(state=DISABLED)
      pb.config(mode='indeterminate')
      pb.start()
      delete.config(state=DISABLED)
      
      for scan_folder in self.scanlist:
        try:
          scanfolder(scan_folder)
        except Exception as ex:
          self.errors += 1

      pb.stop()
      pb.config(mode="determinate")
      delete.config(state=NORMAL)
      deleting.config(text="")
      window.bind("<BackSpace>", delete_action)
      checkbox.place(x=160, y=0)
      scan['command'] = Scan
      if not window.focus_displayof():
        notify("LTecher Antivirus Security", f"Scan Complete\n{str(self.errors)} Errors")

    def full(self):
      self.errors = 0
      checkbox.place(x=100000000, y=10000000000000)
      wait.config(text="")
      window.unbind("<BackSpace>")
      scan['command'] = ""
      pb.config(mode='indeterminate')
      pb.start()
      delete.config(state=DISABLED)

      dirlist = []
      deleting.config(text="Building directory map...")
      for (dirpath, dirnames, filename) in os.walk("/"):
        try:
          dirlist += [os.path.join(dirpath, file) for file in filename]
        except Exception as ex:
          pass
        window.update()

      files = []
      filehashes = []
      for i in dirlist:
        try:
          if i not in files and check_permission(i, "w"):
            window.update()
            deleting.config(text="Scanning: " + str(i))
            window.update()
            if malware_checker(i) != 0:
              virus = []
              virus.append("Malware :: File :: " + i)  # the malware text on the screen
              viruses.insert(0, virus)  # put it in the list box
              viruspath.append(i)
              files.append(i)

          if i not in files and check_permission(i, "w"):
            file_size = os.path.getsize(i)
            window.update()
            if file_size >= 200000000:
              viruses.insert(0, "{Huge file :: File :: " + i + "}")
              files.append(i)

            window.update()

          if i not in files and check_permission(i, "w"):
            if i.endswith(".log") or i.endswith("log.txt") or i.endswith(".save") or i.endswith(
                    ".klg") or i.endswith(".session"):
              viruses.insert(0, "{Junk file :: File :: " + i + "}")
              files.append(i)

          if i not in files and check_permission(i, "w"):
            filehash = md5_hash(i)
            if filehash in filehashes:
              viruses.insert(0, "{Duplicate :: File :: " + i + "}")
              files.append(i)
            else:
              filehashes.append(filehash)
              print(filehashes)

        except Exception as ex:
          pass

      pb.stop()
      pb.config(mode="determinate")
      delete.config(state=NORMAL)
      window.bind("<BackSpace>", delete_action)
      checkbox.place(x=160, y=0)
      scan.config(state=NORMAL)
      if not window.focus_displayof():
        notify("LTecher Antivirus Security", f"Scan Complete\n{str(self.errors)} Errors")

    def custom(self):
      x = 0
      checkbox.place(x=100000000, y=10000000000000)
      path = fd.askdirectory(parent=window)
      wait.config(text="")
      window.unbind("<BackSpace>")
      scan.config(state=DISABLED)
      while True:
        pb.config(mode='indeterminate')
        pb.start()
        delete.config(state=DISABLED)
        try:
          scanfolder(path)
        except Exception as ex:
          if not window.focus_displayof():
            notify("LTecher Antivirus Security", "Scan Complete\n1 Error")

          if messagebox.askretrycancel("Error", "Error: " + str(ex)):
            deleting.config(text="")
            pb.stop()
            pb.config(mode="determinate")
            delete.config(state=NORMAL)
            window.bind("<BackSpace>", delete_action)
          else:
            deleting.config(text="")
            break
        else:
          deleting.config(text="")
          break

      pb.stop()
      pb.config(mode="determinate")
      delete.config(state=NORMAL)
      window.bind("<BackSpace>", delete_action)
      checkbox.place(x=160, y=0)
      scan.config(state=NORMAL)
      if not window.focus_displayof():
        notify("LTecher Antivirus Security", "Scan Complete\n0 Errors")

  scan_engine = engine()

  def Scan():
    scan_menu = Menu(window, tearoff=0)
    scan_menu.add_command(label="Quick Scan", command=scan_engine.quick)
    scan_menu.add_command(label="Full Scan", command=scan_engine.full)
    scan_menu.add_separator()
    scan_menu.add_command(label="Custom Scan", command=scan_engine.custom)

    try:
      scan_menu.tk_popup(x=626, y=460)
    finally:
      scan_menu.grab_release()

  def Delete():
    x = False
    try:
      selected = viruses.get(viruses.curselection())
      selected2 = viruses.curselection()
    except Exception:
      messagebox.showerror("LTecher Antivirus Security", "Please select a item", icon="warning")
      x = True

    if x:
      window.focus_force()
      print(selected)
      print("That previous error don't worry about it")

    if messagebox.askquestion("Delete?", "Are you sure you want to delete this File\nThis cannot be undone!",
                              icon="warning") == "yes":
      window.update()
      window.focus_force()
      window.unbind("<BackSpace>")
      delete.config(state=DISABLED)
      scan.config(state=DISABLED)
      checkbox.place(x=100000000, y=10000000000000)
      while pb['value'] < 100:
        time.sleep(random.randint(0, 5))
        pb['value'] += random.randint(1, 3)
        deleting.config(text="Deleting Selected File(s), Please wait...")
        wait.config(text="")
        window.update()

        try:
          path = json.dumps(selected)

          with open("temp.save", "w+") as f:
            try:
              path.replace("{", "")
              path.replace("}", "")
            finally:
              pass

            f.writelines(path)

          with open("temp.save", "r") as f:
            p = f.read().replace('["Malware :: File :: ', '')
            p = p.replace('"]', '')
            p = p.replace('"{Huge file :: File :: ', '')
            p = p.replace('}"', '')
            p = p.replace('"{Junk file :: File :: ', '')
            p = p.replace('}"', '')
            p = p.replace('"{Duplicate :: File :: ', '')
            p = p.replace('}"', '')
            os.remove("temp.save")

          with open(p, "r+") as f:
            f.truncate(randint(0, 1000))

        except Exception:
          print(" ")

      pb['value'] = 0

      caches = False
      if selected == "{Logs :: File :: ~/Library/Logs}":
        caches = True
        dirlist = []
        for (dirpath, dirnames, filename) in os.walk(home + "/Library/Logs"):
          dirlist += [os.path.join(dirpath, file) for file in filename]
          window.update()

        try:
          for i in dirlist:
            os.remove(i)
        except Exception as ex:
          pass

        viruses.delete(selected2)
        viruses.selection_set(selected2)

        wait.config(text="File has been deleted!")
        deleting.config(text="")
        delete.config(state=NORMAL)
        scan.config(state=NORMAL)
        checkbox.place(x=160, y=0)
        window.bind("<BackSpace>", delete_action)
        if not window.focus_displayof():
          notify("LTecher Antivirus Security", "Delete Complete!")

      elif selected == "{Caches :: File :: ~/Library/Caches}":
        caches = True
        dirlist = []
        for (dirpath, dirnames, filename) in os.walk(home + "/Library/Caches"):
          dirlist += [os.path.join(dirpath, file) for file in filename]
          window.update()

          try:
            for i in dirlist:
              os.remove(i)
          except Exception as ex:
            pass

        viruses.delete(selected2)
        viruses.selection_set(selected2)

        wait.config(text="File has been deleted!")
        deleting.config(text="")
        delete.config(state=NORMAL)
        scan.config(state=NORMAL)
        checkbox.place(x=160, y=0)
        window.bind("<BackSpace>", delete_action)
        if not window.focus_displayof():
          notify("LTecher Antivirus Security", "Delete Complete!")
      else:
        try:
          os.remove(p)
          try:
            viruses.delete(selected2)
          except Exception:
            deleting.config(text="")
            print(bad_print)  # This will stop the function

          viruses.selection_set(selected2)

          wait.config(text="File has been deleted!")
          deleting.config(text="")
          delete.config(state=NORMAL)
          scan.config(state=NORMAL)
          checkbox.place(x=160, y=0)
          window.bind("<BackSpace>", delete_action)
          if not window.focus_displayof():
            notify("LTecher Antivirus Security", "Delete Complete!")
        except Exception as ex:
          viruses.selection_set(selected2)

          wait.config(text="File has been deleted!")
          deleting.config(text="")
          delete.config(state=NORMAL)
          scan.config(state=NORMAL)
          checkbox.place(x=160, y=0)
          window.bind("<BackSpace>", delete_action)
          messagebox.showwarning("Error", "Error: " + str(ex))
    else:
      window.focus_force()

  def delete_action(e):
    Delete()

  def ascii_checker(text):
    try:
      text = text
      text.encode("ascii")
      return True
    except UnicodeEncodeError as ex:
      return False

  def password_manager():
    global password
    password = simpledialog.askstring("Password", "Enter password: ")
    
    root = Tk()
    root.title("Password Manager")
    root.geometry("650x400")
    root.minsize(650, 400)


    tree = ttk.Treeview(root, column=("c1", "c2", "c3"), show='headings')
    tree.pack(fill=BOTH, expand=True)
    
    tree.column("#1", anchor=CENTER)
    
    tree.heading("#1", text="Website")
    
    tree.column("#2", anchor=CENTER)
    
    tree.heading("#2", text="Username")
    
    tree.column("#3", anchor=CENTER)
    
    tree.heading("#3", text="Password")
    
    def reload(once=False):
      for item in tree.get_children():
        tree.delete(item)
        
      passwords = load(open(settings_file, "rb").read())["passwords"]
      
      for k, v in passwords.items():
        if cryptocode.decrypt(v[0], password) != False:
          tree.insert("", tk.END, values=(k, cryptocode.decrypt(v[0], password), cryptocode.decrypt(v[1], password)))
          
          if once == True:
            root.update()
          


    def copy_text(text):
      root.clipboard_clear()
      root.clipboard_append(text)

    def check_password():
      root1 = Tk()
      root1.title("Password Checker")
      root1.resizable(0,0)
      PWNEDURL = "https://api.pwnedpasswords.com/range/{}"
      Label(root1, text="Enter Password to Check").pack()
      entry1 = Entry(root1, width=40)
      entry1.pack()
      label1 = Label(root1, text="Enter Password to Check and click submit")
      label1.pack()
      def get_passwd_digest_pwnd(passwd):
        """
        Check if a given password is in the compromised/reported list and
        return the number of hits, if it's compromised/reported.
        :param passwd: The password that we want to check
        :type passwd: str
        :return: The number of times a password is compromised/reported
        :rtype: int
        """

        sha1 = hashlib.sha1()
        sha1.update(passwd.encode())
        hex_digest = sha1.hexdigest().upper()

        hex_digest_f5 = hex_digest[:5]
        hex_digest_remaining = hex_digest[5:]

        r = requests.get(PWNEDURL.format(hex_digest_f5))

        leaked_passwd_freq = defaultdict(int)

        for passwd_freq in r.content.splitlines():
          pass_parts = passwd_freq.split(b":")
          passwd = pass_parts[0].decode()
          freq = pass_parts[1]
          leaked_passwd_freq[passwd] = int(freq)

        if hex_digest_remaining in leaked_passwd_freq:
          return leaked_passwd_freq[hex_digest_remaining]

        return 0

      def check_password_action():
        try:
          if get_passwd_digest_pwnd(entry1.get()) != 0:
            label1.config(text=f"This password is not safe, it has been hit {get_passwd_digest_pwnd(entry1.get())} times")
          else:
            label1.config(text="This password is safe!")
        except requests.exceptions.ConnectionError as ex:
          label1.config(text="There has been a error with connecting, please make sure the antivirus can access the internet")

      Button(root1, text="submit", command=check_password_action).pack()


    def pass_gen():
      root1 = Tk()
      root1.title("Genarate Password")
      root1.geometry("360x140")
      root1.resizable(0,0)
      Label(root1, text="length").pack()
      get_length = Scale(root1, from_=0, to=100, orient='horizontal')
      get_length.pack()
      show_password = Label(root1, text="Enter length and click Genarate")
      show_password.pack()
      characters = list(string.ascii_letters + string.digits + "!@#$%^&*()")

      def generate_random_password(length):
        ## length of password from the user

        ## shuffling the characters
        random.shuffle(characters)

        ## picking random characters from the list
        password = []
        for i in range(length):
          password.append(random.choice(characters))

        ## shuffling the resultant password
        random.shuffle(password)

        ## converting the list to string
        ## printing the list
        return "".join(password)

      def copy_pass():
        root1.clipboard_clear()
        root1.clipboard_append(show_password.cget("text"))



      Button(root1, text="Generate", command=lambda:show_password.config(text=generate_random_password(get_length.get()))).pack()
      Button(root1, text="Copy", command=copy_pass).pack()
      root1.mainloop()

    password_menubar = Menu(root)

  

    def open_url():
      print(str(tree.item(tree.focus(), "values")))
      if tree.item(tree.focus(), "values")[0].startswith("https://") or str(str(tree.item(tree.focus(), "values")).split(": ")[0][0]).startswith("https://"):
        webbrowser.open(tree.item(tree.focus(), "values")[0])
      else:
        webbrowser.open("https://" + tree.item(tree.focus(), "values")[0])

    def copy_url():
      copy_text(tree.item(tree.focus(), "values")[0])

    def copy_user():
      copy_text(tree.item(tree.focus(), "values")[1])

    def copy_pass():
      copy_text(tree.item(tree.focus(), "values")[2])

    def db_to_json():
      items = load(open(settings_file, "rb").read())["passwords"]
      cur_value = 0
      json_output = {}
      
      for k, v in items.items():
        cur_value += 1
        json_output[str(cur_value)] = (k, v[0], v[1])
      
      return json_output


    def export():
      try:
        open(filedialog.asksaveasfilename(), "w").write(json.dumps(db_to_json()))
      except Exception as ex:
        print(ex)

    def import_database():
      try:
        cur_data = load(open(settings_file, "rb").read())
        cur_passwords = load(open(settings_file, "rb").read())["passwords"]
        
        json_items = json.load(open(filedialog.askopenfilename(filetypes=(("Json Files", "*.json"), ("All Files", "*.*"))), "r"))
        
        for k, v in json_items.items():
          cur_passwords[v[0]] = (v[1], v[2])
        
        cur_data["passwords"] = cur_passwords
        open(settings_file, "wb").write(save(cur_data))
        
        messagebox.showinfo("Alert", "Import complete!\nPlease restart the password manager.")
      except:
        pass
        
    def add_pass():
      website = simpledialog.askstring("Input", "Website: ")
      username = cryptocode.encrypt(simpledialog.askstring("Input", "Username: "), password)
      input_password = cryptocode.encrypt(simpledialog.askstring("Input", "Password: "), password)
      
      cur_data = load(open(settings_file, "rb").read())
      cur_pass = load(open(settings_file, "rb").read())["passwords"]
      
      cur_pass[website] = (username, input_password)
      cur_data["passwords"] = cur_pass
      
      
      open(settings_file, "wb").write(save(cur_data))
      
      reload()
    
    def delete():
      cur_passwords = load(open(settings_file, "rb").read())["passwords"]
      cur_data = load(open(settings_file, "rb").read())
      
      if messagebox.askyesno("Delete", "Are you sure you want to delete this password?"):
        try:
          del cur_passwords[tree.item(tree.focus(), "values")[0]]
        except Exception as ex:
          messagebox.showwarning("Error", "Error: " + str(ex))
        else:
          cur_data["passwords"] = cur_passwords
          open(settings_file, "wb").write(save(cur_data))
          reload()


    toolsmenu = Menu(password_menubar)
    toolsmenu.add_command(label="Generate Password...", command=pass_gen)
    toolsmenu.add_command(label="Check Password...", command=check_password)
    toolsmenu.add_separator()
    urlmenu = Menu(toolsmenu)
    urlmenu.add_command(label="Open Url", command=open_url)
    urlmenu.add_command(label="Copy Url", command=copy_url)
    password_menubar.add_cascade(menu=toolsmenu, label="Tools")
    toolsmenu.add_cascade(menu=urlmenu, label="URL")
    toolsmenu.add_command(label="Copy Username", command=copy_user)
    toolsmenu.add_command(label="Copy Password", command=copy_pass)
    toolsmenu.add_separator()
    toolsmenu.add_command(label="Add", command=add_pass)
    toolsmenu.add_command(label="Delete", command=delete)
    toolsmenu.add_separator()
    toolsmenu.add_command(label="Import...", command=import_database)
    toolsmenu.add_command(label="Export...", command=export)
    root.config(menu=password_menubar)
    
    def do_popup(event):
      try:
        toolsmenu.tk_popup(event.x_root, event.y_root)
      finally:
        toolsmenu.grab_release()
    
    root.bind("<Button-3>", do_popup)
    root.bind("<Button-2>", do_popup)
    
    
    def login(e):
      global password
      password = simpledialog.askstring("Password", "Enter password: ")
      reload(once=True)
      
    root.bind("<Control-l>", login)
    
    reload(once=True)

    


    root.mainloop()

  def prefences():
    
    root = Toplevel()
    root.geometry("400x250")
    root.resizable(0,0)
    root.title("Prefences")
    junk_clean = IntVar()
    junk_clean.set(get_clean_caches_question().replace(\
      "yes", "1").replace("no", "0"))
    tabControl = ttk.Notebook(root)
    tab1 = ttk.Frame(tabControl)
    tab2 = ttk.Frame(tabControl)
    tab3 = ttk.Frame(tabControl)
    tab4 = ttk.Frame(tabControl)
    tabControl.add(tab4, text='Ignore')
    tabControl.add(tab1, text='Customize')
    tabControl.add(tab2, text='Scanning')
    tabControl.add(tab3, text='Cleaning')
    tabControl.pack(expand=1, fill="both")
    ChkBttn = ttk.Checkbutton(tab3, width = 15, variable = junk_clean, text="Clean Junk")
    ChkBttn.pack(padx = 5, pady = 5)
    
    files = get_ingore_values()
    Label(tab4, text="Ignore List").pack()
    listbox1 = Listbox(tab4, height=10)
    listbox1.insert("end", *files)
    listbox1.pack(fill=BOTH, pady=10)
    
    def add_file():
      for i in filedialog.askopenfilenames():
        files.append(i)
      try:
        listbox1.delete(0, "end")
      except:
        pass
      listbox1.insert("end", *files)
      
    def delete_file():
      files.remove(listbox1.get(listbox1.curselection()))
      try:
        listbox1.delete(0, "end")
      except:
        pass
      listbox1.insert("end", *files)
    
    Button(tab4, text="Add...", command=add_file).place(x=0, y=0)
    Button(tab4, text="Delete", command=delete_file).place(x=270, y=0)
    
    def save_data():
      curr_data = {
        "theme": [get_color(), int(get_checked_value())],
        "ingore_list": [get_clean_caches_question(), str(get_ingore_values())],
        "passwords": load(open(settings_file, "rb").read())["passwords"]
      }
      
      
      curr_data["ingore_list"][0] = str(junk_clean.get()).replace("1",\
        "yes").replace("0", "no")
      curr_data["ingore_list"][1] = str(files)
      
      open(settings_file, "wb").write(save(curr_data))
      
      root.destroy()
      
    root.protocol("WM_DELETE_WINDOW", save_data)

  def update_program():
    open(__file__, "wb").write(requests.get("https://ltws.w3spaces.com/antivirus.txt").content)
    if open(__file__, "r").read() == antivirus_code:
      messagebox.showinfo("Antivirus Updates", "You are up to date!")
    else:
      messagebox.showinfo("Antivirus Updates", "Antivirus Updated Successfuly")

  def url_checker():
    with open("url_database.txt", "r") as f:
      malware_urls_read = f.read()
      text = simpledialog.askstring("Url checker", "Enter url").replace("https://www.", "").replace("https://",
        
  
                                                                                                    "").replace(
        "/", "")
      if malware_urls_read.find(text) != -1 or ascii_checker(text) is not True:
        messagebox.showwarning(title=None, message="This is not a safe url")
      else:
        messagebox.showinfo(title=None, message="This is a safe url")

  def kill_process():
    try:
      os.system("killall " + simpledialog.askstring("Kill task", "Enter task to kill").replace(" ", "\ "))
    except Exception as ex:
      messagebox.showwarning("Error", "Error: " + str(ex))

  def create_task():
    for i in filedialog.askopenfilenames():
      os.system("open " + i.replace(" ", "\ "))

  def reset():
    if messagebox.askyesno("Alert", "Are you sure you want to reset this app?"):
      os.remove(home + "/LTecher Antivirus Security/settings.dat")
      messagebox.showinfo("Alert", "Reset complete!\nPlease restart the app.")

  def RamBooster():
    killlist = ["Mail", "Google\ Chrome", "Safari", "BluetoothUIServer", "bluetoothd", "Siri", "uTorrent\ Web",
                "Photos", "TV", "CoreSync"]

    if messagebox.askyesno("", "Are you sure you wanna boost memory"):
      for task in killlist:
        os.system("killall " + task)
  
  def encrypt_bytes(message: bytes, key: str):
    return cryptocode.encrypt(base64.b64encode(message).decode(), key)
  
  def decrypt_bytes(message: bytes, key: str):
    return cryptocode.decrypt(base64.b64decode(message).decode(), key)
  
  def file_encryption():
    global encrypt_pass
    encrypt_pass = simpledialog.askstring("Password", "Password: ")
    
    root = Toplevel()
    
    root.title("File Safe")
    root.geometry("400x250")
    root.resizable(0,0)
    
    tree = ttk.Treeview(root, column=("c1", "c2"), show='headings')
    tree.pack(fill=BOTH, expand=True)
    
    tree.column("#1", anchor=CENTER)
    
    tree.heading("#1", text="Name")
    
    tree.column("#2", anchor=CENTER)
    
    tree.heading("#2", text="Viewable")
    
    toolsmenu = Menu(root, tearoff=0)
    
    def reload_files():
      for item in tree.get_children():
        tree.delete(item)
      
      files = load(open(vault_file, "rb").read())
      
      for k, v in files.items():
        try:
          base64.b64decode(cryptocode.decrypt(v, encrypt_pass)).decode()
        except UnicodeDecodeError:
          view = False
        else:
          view = True
        
        tree.insert("", tk.END, values=(k, str(view)))
        
    def save_file():
      save_as = fd.asksaveasfilename()
      files = load(open(vault_file, "rb").read())
      
      open(save_as, "wb").write(base64.b64decode(cryptocode.decrypt(files[tree.item(tree.focus(), "values")[0]], encrypt_pass)))
        
    def add_encrypted():
      cur_files = load(open(vault_file, "rb").read())
      
      
      add_file = fd.askopenfilename(parent=root)
      
      data = encrypt_bytes(open(add_file, "rb").read(), encrypt_pass)
      
      cur_files[os.path.basename(add_file)] = data
      
      
      open(vault_file, "wb").write(save(cur_files))
      
      reload_files()
      
        
    def view():
      try:
        if tree.item(tree.focus(), "values")[1] == "True":
          files = load(open(vault_file, "rb").read())
          
          root1 = Toplevel()
          
          root1.title("View")
          root1.resizable(0,0)
          root1.geometry("400x250")
          
          text = Text(root1)
          text.insert("end", base64.b64decode(cryptocode.decrypt(files[tree.item(tree.focus(), "values")[0]], encrypt_pass)).decode())
          text.config(state=DISABLED)
          text.pack(expand=True)
        else:
          messagebox.showinfo("Alert", "You cannot view this file")
      except:
        pass
        
    def delete_file():
      cur_files = load(open(vault_file, "rb").read())
      
      if messagebox.askyesno("Alert", "Are you sure you want to delete this file?"):
        del cur_files[tree.item(tree.focus(), "values")[0]]
        
        
        open(vault_file, "wb").write(save(cur_files))
        
        reload_files()
        
    toolsmenu.add_command(label="Save as", command=save_file)
    toolsmenu.add_command(label="Delete", command=delete_file)
    toolsmenu.add_command(label="View", command=view)
    toolsmenu.add_command(label="Add", command=add_encrypted)
      
    def do_popup(event):
      try:
        toolsmenu.tk_popup(event.x_root, event.y_root)
      finally:
        toolsmenu.grab_release()
        
    root.bind("<Button-3>", do_popup)
    root.bind("<Button-2>", do_popup)
    
    reload_files()
      
      

  def backup():
    with zipfile.ZipFile(filedialog.asksaveasfilename(title="Enter name for backup", filetypes=(("Zip files", "*.zip"), ("All files", "*.*"))),
                         "w") as f:
      for file in filedialog.askopenfilenames(title="Select files for backup"):
        f.write(file)

      if window.focus_displayof():
        notify("LTecher Antivirus Security", "Backup Complete!")
      else:
        messagebox.showinfo("LTecher Antivirus Security", "Backup Complete!")

  def open_cloud():
    os.system("open ftp_launcher.command")

  def startup_programs():
    root = Tk()
    root.resizable(0, 0)
    root.title("Startup Manger")
    root.geometry("600x200")
    listbox1 = Listbox(root, width=80)
    listbox1.pack()
    programs = os.listdir(home + "/Library/LaunchAgents")
    for p in programs:
      listbox1.insert('end', p)

    def delete_program():
      try:
        os.remove("{}/Library/LaunchAgents/{}".format(home, listbox1.get(listbox1.curselection())))

        listbox1.delete(listbox1.curselection())
      except Exception as ex:
        pass

    Button(root, text="Delete", command=delete_program).pack()
    root.mainloop()

  # window
  global window
  window = Tk()
  menu = Menu(window)
  window.config(menu=menu)
  window.createcommand('tk::mac::ShowPreferences', prefences)
  
  filemenu = Menu(menu)
  filemenu.add_command(label="Scan", command=Scan)
  filemenu.add_command(label="Delete", command=Delete)
  filemenu.add_command(label="Reset", command=reset)
  filemenu.add_separator()
  filemenu.add_command(label="Exit", command=exit)
  
  utilsmenu = Menu(menu)
  utilsmenu.add_command(label="Check for Updates...", command=update_program)
  utilsmenu.add_command(label="Password Manager...", command=password_manager)
  utilsmenu.add_command(label="Create New Task...", command=create_task)
  utilsmenu.add_command(label="Startup Manger...",
    command=startup_programs)
  utilsmenu.add_command(label="Ram Booster...", 
    command=RamBooster)
  utilsmenu.add_command(label="Url Checker...", command=url_checker)
  utilsmenu.add_command(label="File Safe...", command=file_encryption)
  utilsmenu.add_command(label="End Task...", command=kill_process)
  utilsmenu.add_command(label="Backup...", command=backup)
  menu.add_cascade(label="File", menu=filemenu)
  menu.add_cascade(label="Tools", menu=utilsmenu)

  def exit_action(window):
    if checkbox_var.get() == 1:
      window.destroy()
      window.update()
      no_scan_files = get_ingore_values()
      with open("Backup of Antivirus.txt", "w+") as f:
        f.writelines(antivirus_code)

      while True:
        dirlist = []

        root = "{}/Downloads".format(home)

        for root, dirs, files in os.walk(root):
          for f in files:
            dirlist.append(os.path.join(root, f))

        def exit_virus_doilog():
          no_scan_files.append(i)
          window.destroy()

        for i in dirlist:
          if i not in no_scan_files and not i.endswith(".crdownload") and not i.endswith(".part"):
            if os.path.exists(i):
              if malware_checker(i) != 0:
                virus = []


                def delete():
                  os.remove(i)
                  window.destroy()
                  window.update()

                window = Tk()
                window.protocol("WM_DELETE_WINDOW", exit_virus_doilog)
                window.resizable(0, 0)
                window.title("Real-Time Protection")
                window.geometry("800x600")
                Button(window, text="Delete", width=10, height=2, command=delete).place(x=328, y=300)
                Label(window, text=f"Virus Detected in {i}",
                      font=("Raleway", 20, "bold")).pack()
                Label(window, text=md5_hash(i)).place(x=0, y=560)
                window.mainloop()
    else:
      window.destroy()

  def update_real_time():
    cur_data = load(open(settings_file, "rb").read())
    cur_data["theme"][1] = checkbox_var.get()
    
    open(settings_file, "wb").write(save(cur_data))

  checkbox_var = IntVar()
  checkbox_var.set(int(get_checked_value()))
  global checkbox
  checkbox = Checkbutton(window, onvalue=1, offvalue=0, variable=checkbox_var, text="real-time-protection",
                         command=update_real_time)
  checkbox.place(x=160, y=0)
  global deleting
  deleting = Label(window, text="")
  global wait
  wait = Label(window, text="", fg="#00ff52")
  frm = ttk.Frame(window, padding=10)
  wait.place(x=360, y=7)
  deleting.place(x=6, y=7)
  frm.grid()
  window.title("LTecher Antivirus Security")
  window.geometry("550x300+420+200")
  window.maxsize(width="500", height="300")
  window.minsize(width="500", height="300")
  window.resizable(False, False)
  window.bind("<BackSpace>", delete_action)
  global delete
  global scan
  scan = Button(window, text="Scan Now", command=Scan)
  delete = Button(window, text="Delete", command=Delete)
  Quit = Button(window, text="Exit", command=lambda:exit_action(window))
  global viruses
  viruses = Listbox(window, fg=get_color())
  if get_clean_caches_question() == "yes":
    viruses.insert('end', "{Caches :: File :: ~/Library/Caches}")
    viruses.insert('end', "{Logs :: File :: ~/Library/Logs}")
  viruses.place(x=50, y=30, height=220, width=400)
  global pb
  pb = ttk.Progressbar(window, orient='horizontal', mode='determinate', length=400)
  delete.place(x=126, y=260)
  Quit.place(x=300, y=260)
  scan.place(x=202, y=260)
  pb.place(x=50, y=250)
  try:
    if sys.argv[1].lower() == "-s":
      while True:
        try:
          scanfolder(sys.argv[2])
          break
        except Exception as ex:
          print("Scan aborted: " + str(ex))
          choice = input("Try again: ")
          if choice == "y" or choice == "yes":
            pass
          else:
            sys.exit(1)
    elif sys.argv[1].lower() == "-v":
      print("LTecher Antivirus Security\nCopyright 2022 LTecher\nversion 1.0")
      sys.exit(0)
    elif sys.argv[1].lower() == "-k":
      os.system("killall " + sys.argv[2].replace(" ", "\ "))
      sys.exit(0)
    elif sys.argv[1].lower() == "-h":
      print(
        "usage: -k: kills a process you input, -s: scans a folder you input, -v: shows the current version, -u: update the program, -o: open a file or folder or app")
      sys.exit(0)
    elif sys.argv[1].lower() == "-u":
      update_program()
      sys.exit(0)
    elif sys.argv[1].lower() == "-o":
      os.system("open " + sys.argv[2].replace(" ", "\ "))
      sys.exit(0)
    else:
      print("Invalid Argument: " + sys.argv[1].lower())
      sys.exit(1)
  except Exception as ex:
    pass

  window.mainloop()


if os.path.exists(settings_file):
  main()
else:
  root = Tk()
  root.geometry("600x300")
  root.resizable(0, 0)
  root.title("LTecher Antivirus Security setup")


  def run_setup():
    color = askcolor(title="Select color for virus listbox")
    
    save_dict = {
      "theme": [color[1], 1],
      "ingore_list": [messagebox.askquestion("Question", "Do you want to clean junk?"), "[]"],
      "passwords": {}
    }
    
    open(settings_file, "wb").write(save(save_dict))
    open(vault_file, "wb").write(save({}))

    root.destroy()


  Button(root, text="Next", command=run_setup).place(x=0, y=260)
  Label(root, text="""Welcome to LTecher Antivirus Security
	This Product is free of charge but cannot be modified for
	Security reasons email lawrencewilliams1030@gmail.com
	any new ideas,
	Click Next to continue""").pack()
  root.mainloop()
  main()