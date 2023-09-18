import tkinter as tk
from tkinter import messagebox
from tkinter import *
from tkinter import filedialog
from PIL import ImageTk, Image
from Crypto.Util.number import long_to_bytes, bytes_to_long
import datetime as _dt
import math
import falcon_2
import qrcode
import cv2
import sys
import hashlib
from firebase_admin import credentials
from firebase_admin import firestore
import firebase_admin
from Crypto import Random
from Crypto.Cipher import AES
from base64 import b64encode, b64decode
def test():
	pass
class Authorize:
	file_name = "default"
	def __init__(self):
		self.root = tk.Tk()
		self.root.title("Authorize")
		self.root.geometry("300x300")
		self.root.config(bg="LightGreen")

		self.button = tk.Button(self.root, text="Choose file json", font=('Arial', 14), command=self.choosefile)
		self.button.pack(padx=10,pady=10)

		self.root.mainloop()
	def choosefile(self):
		filetypes = (
				('json', '*.json'),
				('All files', '*.*')
			)
		filename = filedialog.askopenfilename(filetypes=filetypes)
		name = str(filename)
		self.file_name = name
		self.root.destroy()

a = Authorize()
#credpath = r"C:\DoAn_MMH\doanmmh-firebase-adminsdk-gm8or-1d3f6d258d.json"
credpath = a.file_name
login = credentials.Certificate(credpath)

#intialize firebase
firebase_admin.initialize_app(login)

db = firestore.client()
class AES_GCM(object):
	def __init__(self, password):
		self.key = hashlib.sha256(password.encode()).digest()
	def encrypt(self, plaintext, mode):
		encobj = AES.new(self.key, AES.MODE_GCM)
		ciphertext,authTag=encobj.encrypt_and_digest(plaintext)
		return(ciphertext,authTag,encobj.nonce)
	def decrypt(self, ciphertext, mode):
		(ciphertext,  authTag, nonce) = ciphertext
		encobj = AES.new(self.key,  mode, nonce)
		return(encobj.decrypt_and_verify(ciphertext, authTag))

class GenerateQR:
	def __init__(self, nameuser):
		self.root = tk.Tk()
		self.root.title("QR Code Generate")
		self.root.geometry("700x700")
		self.root.config(bg='LightGreen')

		self.nameuser = nameuser


		self.labelsecret = tk.Label(self.root, text="Choose file to get key")
		self.labelsecret.place(x=20,y=550)

		self.entrysecret = tk.Entry(self.root,font=('Arial', 14))
		self.entrysecret.place(x=20,y=580)

		self.buttonsecret = tk.Button(self.root,text="Click to find",font=('Arial', 14), command=self.open_file)
		self.buttonsecret.place(x=20,y=610)

		self.label1 = tk.Label(self.root,text="Choose file to sign: ", font=('Arial', 14, 'bold'))
		self.label1.pack(padx=10,pady=10)

		self.dirfile = tk.Entry(self.root, font=('Arial', 14))
		self.dirfile.pack(padx=10,pady=10)

		self.buttonfile = tk.Button(self.root, text="Select File", font=('Arial', 14, 'bold'), command=self.choosefile)
		self.buttonfile.pack(padx=10,pady=10)

		self.label2 = tk.Label(self.root,text="Hash value of file", font=('Arial', 14))
		self.label2.pack(padx=10,pady=10)

		self.textbox = tk.Text(self.root,height=2, font=('Arial', 14))
		self.textbox.pack(padx=10,pady=10)

		self.label3 = tk.Label(self.root,text="Signature", font=('Arial', 14))
		self.label3.pack(padx=10,pady=10)

		self.textbox1 = tk.Text(self.root,height=2, font=('Arial', 14))
		self.textbox1.pack(padx=10,pady=10)

		self.buttonframe = tk.Frame(self.root)
		self.buttonframe.columnconfigure(0, weight=1)
		

		self.buttonsign = tk.Button(self.buttonframe, text="Sign", font=('Arial', 14, 'bold'), command=self.sign)
		self.buttonsign.grid(sticky='w',row=0, column=0)

		self.buttonhash = tk.Button(self.buttonframe, text="Hash", font=('Arial', 14, 'bold'), command=self.hash)
		self.buttonhash.grid(sticky='e',row=0, column=1)

		self.buttonframe.pack(padx=10,pady=10)

		self.labelframe = tk.Frame(self.root)
		self.labelframe.columnconfigure(0, weight=1)
		self.labelframe.columnconfigure(1, weight=1)

		self.label4 = tk.Label(self.labelframe, text='Location of QR code', font=('Arial', 14))
		self.label4.grid(row=0, column=0)

		self.loc = tk.Entry(self.labelframe, font=('Arial', 12))
		self.loc.grid(row=1, column=0)

		self.label5 = tk.Label(self.labelframe, text='Name of QR Code', font=('Arial', 14))
		self.label5.grid(row=0, column=1)

		self.name = tk.Entry(self.labelframe, font=('Arial', 12))
		self.name.grid(row=1, column=1)

		self.labelframe.pack(padx=10,pady=10)

		self.buttoncreate = tk.Button(self.root, text="Generate QR",font=('Arial', 14, 'bold'), command=self.generateQR)
		self.buttoncreate.pack(padx=10,pady=10)

		self.check_state = tk.IntVar()

		self.root.protocol("WM_DELETE_WINDOW", self.on_closing)
		self.root.mainloop()

	def on_closing(self):
		if messagebox.askyesno(title="Quit ?", message="Do you really want to quit?"):
			self.root.destroy()
	def choosefile(self):
		filetypes= (
				('docx', '*.docx'),
				('All files', '*.*')
			)
		filename = filedialog.askopenfilename(filetypes=filetypes)
		name = str(filename)
		self.dirfile.delete(0,END)
		self.dirfile.insert(0, name)
	
	def open_file(self):
		filetypes={
			('txt', '*.txt'),
			('All files', '*.*')
		}
		filename = filedialog.askopenfilename(filetypes=filetypes)
		name = str(filename)
		self.entrysecret.delete(0, END)
		self.entrysecret.insert(0, name)
	def sign(self):
		filename = self.entrysecret.get()
		try:
			with open(filename,"r") as f:
				string = f.read()
			a = string
			b = a.split(', ')
			c = []
			for i in b:
				result = 0
				check = False
				for j in i:
					if j == '-':
						check = True
						continue
					result *= 10
					result += ord(j) - ord('0')
				if check == True:
					result = -result
				c.append(result)
			f = c[:256]
			g = c[256:512]
			F = c[512:768]
			G = c[768:]
			sk = falcon_2.SecretKey(256, f, g, F, G)
			if self.textbox.get('1.0', tk.END) == "":
				messagebox.showinfo("Error", "Compute hash value of file")
			else:
				string = self.textbox.get('1.0', tk.END)
				string = bytes.fromhex(string)
				sig = sk.sign(string)
				sig_hex = sig.hex()
				self.textbox1.delete('1.0', tk.END)
				self.textbox1.insert(tk.END, sig_hex)
				messagebox.showinfo("Signing","Signing is successfull!")
		except Exception as e:
			messagebox.showinfo("Error","Can't find secret key")
	def hash(self):
		filename = self.dirfile.get()
		string = ""
		with open(filename,"rb") as f:
			bytes_str = f.read()
			readable_hash = hashlib.sha256(bytes_str).hexdigest()
			string = readable_hash
		self.textbox.delete('1.0',tk.END)
		self.textbox.insert(tk.END, string)
	def generateQR(self):
		if self.loc.get()=="" or self.name.get()=="":
			messagebox.showinfo("Error", "Input location of name of image")
		else:
			qr = qrcode.QRCode(version = 1,box_size=5, border=5)
			qr.add_data(self.textbox1.get('1.0', tk.END))
			qr.make(fit = True)
			img = qr.make_image()
			fileDirec=self.loc.get()+'\\'+self.name.get()
			img.save(f'{fileDirec}.png')
			messagebox.showinfo("Generate QR code", "Successfull")
			docs = db.collection("publickey_user").stream()
			position = ""
			for i in docs:
				doc = i.to_dict()
				hovaten = doc['hovaten']
				if hovaten == self.nameuser:
					position = doc['chucvu']
			data = {
				"hovaten": self.nameuser,
				"chucvu": position,
				"date": str(_dt.datetime.now()),
				"ten_van_ban": self.name.get(),
			}
			db.collection("Signing_History").document().set(data)

class VerifyQR:
	pk = [0]
	def __init__(self):
		self.root = tk.Tk()
		self.root.geometry("600x600")

		self.label1 = tk.Label(self.root, text="QR code image", font=('Arial', 14))
		self.label1.pack(padx=10,pady=10)

		self.showdir = tk.Entry(self.root, font=('Arial', 14))
		self.showdir.pack(padx=10,pady=10)

		self.open_button = tk.Button(self.root, text="Choose Image", command=self.open_qr)
		self.open_button.pack(padx=10,pady=10)

		self.label2 = tk.Label(self.root,text="Input directory to file", font=('Arial', 14))
		self.label2.pack()

		self.dirfile = tk.Entry(self.root,font=('Arial', 14))
		self.dirfile.pack(padx=10,pady=10)

		self.label3 = tk.Label(self.root, text="Hash value of file", font=('Arial', 14))
		self.label3.pack(padx=10,pady=10)

		self.textbox = tk.Text(self.root, height=2, font=('Arial', 14))
		self.textbox.pack(padx=10,pady=10)

		self.buttonframe = tk.Frame(self.root)
		self.buttonframe.columnconfigure(0, weight=1)

		self.buttondir = tk.Button(self.buttonframe,text="Select File", font=('Arial', 14, 'bold'), command=self.open_file)
		self.buttondir.grid(sticky='w',row=0,column=0)

		self.hashbutton = tk.Button(self.buttonframe,text="Hash File", font=('Arial', 14, 'bold'), command=self.hashfile)
		self.hashbutton.grid(row=0,column=1)

		self.buttonverify = tk.Button(self.buttonframe,text="Verify", font=('Arial', 14, 'bold'), command=self.verify_qr)
		self.buttonverify.grid(sticky='e',row=0,column=2)

		self.labelinfo = tk.Label(self.root, text="Information of Signer", font=('Arial', 14))
		self.labelinfo.pack(padx=10,pady=10)

		self.textinfo = tk.Text(self.root, height=2, font=('Arial', 14))
		self.textinfo.pack(padx=10,pady=10)

		self.buttonclear = tk.Button(self.root,text="Clear", font=('Arial', 14, 'bold'), command=self.clear)
		self.buttonclear.pack(padx=10,pady=10)

		self.buttonframe.pack(fill='x',padx=10,pady=10)

		self.root.mainloop()
	def open_qr(self):
		filetypes= (
				('jpeg', '*.jpg'),
				('All files', '*.*')
			)
		filename = filedialog.askopenfilename(filetypes=filetypes)
		name = str(filename)
		self.showdir.delete(0,END)
		self.showdir.insert(0, name)
	def verify_qr(self):
		check = False
		check_before = False
		information = ""
		detector = cv2.QRCodeDetector()
		path = self.showdir.get()
		img = cv2.imread(path)
		reval, point, s_qr = detector.detectAndDecode(img)
		string = self.textbox.get('1.0', tk.END)
		docs = db.collection("publickey_user").stream()
		for i in docs:
			doc = i.to_dict()
			pkey = doc['publickey']
			pk = falcon_2.PublicKey(256,pkey)
			try:
				check_before = pk.verify(bytes.fromhex(string), bytes.fromhex(reval))
			except Exception as e:
				check_before = False
			check = check_before
			if check==True:
				dicts = db.collection("Signing_History").stream()
				for j in dicts:
					item = j.to_dict()
					k = len(path)-1
					string_temp = ""
					tenvanban = ""
					while(k>0):
						if path[k] != "/":
							string_temp += path[k]
						else:
							t = len(string_temp)-1
							while(t>0):
								if string_temp[t]!='.':
									tenvanban += string_temp[t]
								else:
									break
								t -= 1
							break
						k -= 1
					
					if item['hovaten'] == doc.get('hovaten') and item['ten_van_ban'] == tenvanban:
						information = "Ho va ten: " + item.get('hovaten') + ", chuc vu: " + item.get('chucvu') + ", ngay ky: " + item.get('date')
						break 
				self.textinfo.delete('1.0',tk.END)
				self.textinfo.insert(tk.END,information)
				messagebox.showinfo("Verifying QR","Valid")
				break
			
		if check == False:
			messagebox.showinfo("Verifying QR","Invalid")
	def open_file(self):
		filetypes= (
			    ('docx', '*.docx'),
				('All files', '*.*')
			)
		filename = filedialog.askopenfilename(filetypes=filetypes)
		name = str(filename)
		self.dirfile.delete(0,END)
		self.dirfile.insert(0, name)
	def hashfile(self):
		filename = self.dirfile.get()
		string = ""
		with open(filename,"rb") as f:
			bytes_str = f.read()
			readable_hash = hashlib.sha256(bytes_str).hexdigest()
			string = readable_hash
		self.textbox.delete('1.0', tk.END)
		self.textbox.insert(tk.END, string)
	def clear(self):
		self.textbox.delete('1.0', tk.END)
		self.showdir.delete(0,END)
		self.dirfile.delete(0,END)
		self.textinfo.delete('1.0', tk.END)
class LoginForm:
	check = 0
	nameuser = "hau"
	def __init__(self):
		self.root = tk.Tk()
		self.root.title("Login Form")
		self.root.geometry("1199x600+100+50")
		self.root.config(bg = 'LightBlue')

		self.buttonuser = tk.Button(self.root, text="Use as user", font=('Arial', 16, "bold"), command=self.modeuser)
		self.buttonuser.pack(padx=10,pady=10)

		self.frameLogin = tk.Frame(self.root, bg = "White")
		self.frameLogin.place(x=330, y=150, width=500, height=400)
		
		self.titlelabel = tk.Label(self.frameLogin, text="Login Here", font=('Arial', 16, "bold"))
		self.titlelabel.place(x=90,y=30)

		self.userlabel = tk.Label(self.frameLogin, text="Username", font=('Arial', 16))
		self.userlabel.place(x=90,y=120)

		self.username = tk.Entry(self.frameLogin, font=('Arial', 14))
		self.username.place(x=90,y=170,width=320, height=35)

		self.passlabel = tk.Label(self.frameLogin, text="Password", font=('Arial', 16))
		self.passlabel.place(x=90,y=210, width=320, height=35)

		self.password = tk.Entry(self.frameLogin, font=('Arial', 14),show="*")
		self.password.place(x=90,y=240, width=320, height=35)

		self.buttonlogin = tk.Button(self.frameLogin, text="Login", font=('Arial', 16, "bold"), command=self.login)
		self.buttonlogin.place(x=200, y=300, width=200, height=40)

		self.root.mainloop()
	def login(self):
		docs = db.collection("Login_Info").stream()
		for i in docs:
			doc = i.to_dict()
			name = doc.get('username')
			if name == self.username.get():
				a = doc.get('ciphertext')
				b = doc.get('authTag')
				c = doc.get('nonce')
				ciphertext = (bytes.fromhex(a), bytes.fromhex(b), bytes.fromhex(c))
				key = self.password.get()
				aes = AES_GCM(key)
				pt = aes.decrypt(ciphertext, AES.MODE_GCM)
				
				if pt.decode() == name:
					self.nameuser = doc.get('hovaten')
					self.check = 1
					break
		if self.check == 1:
			messagebox.showinfo("Result","Login thanh cong")
			self.root.destroy()
		else:
			messagebox.showinfo("Result","Sai mat khau")
	def modeuser(self):
		self.check = 2
		self.root.destroy()
l = LoginForm()

if l.check==1:
	g = GenerateQR(l.nameuser)
elif l.check==2:
	v = VerifyQR()
