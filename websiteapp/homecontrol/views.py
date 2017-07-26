# -*- coding: utf-8 -*-
from __future__ import unicode_literals

from django.shortcuts import render
from django.http import HttpResponse
from django.views.decorators.csrf import csrf_exempt

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA512
import base64
import hashlib
import random, string
from random import randint

def shared_aes_encryption_generate():
	temp=""
	keyspace = '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'
	for i in range(0,12):
		temp += keyspace[randint(0,len(keyspace)-1)]
	return temp
def encrypt_RSA(public_key_loc, message):
	'''
	param: public_key_loc Path to public key
	param: message String to be encrypted
	return base64 encoded encrypted string
	'''
	key = open(public_key_loc, "r").read()
	rsakey = RSA.importKey(key)
	rsakey = PKCS1_OAEP.new(rsakey)
	encrypted = rsakey.encrypt(message)
	return encrypted.encode('base64')
#----------------------------------------------
#AES Encryption Class
#----------------------------------------------
class AESCipher:

	def __init__(self, key):
		self.bs = 16
		self.key = hashlib.sha256(key.encode()).digest()

	def encrypt(self, message):
		message = self._pad(message)
		iv = Random.new().read(AES.block_size)
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return base64.b64encode(iv + cipher.encrypt(message)).decode('utf-8')

	def decrypt(self, enc):
		enc = base64.b64decode(enc)
		iv = enc[:AES.block_size]
		cipher = AES.new(self.key, AES.MODE_CBC, iv)
		return self._unpad(cipher.decrypt(enc[AES.block_size:])).decode('utf-8')

	def _pad(self, s):
		return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

	@staticmethod
	def _unpad(s):
		return s[:-ord(s[len(s)-1:])]

# Create your views here.
def index(request):
	return render(request, "loginpage.html")

@csrf_exempt
def rsaencryption(request):
	if request.method=='POST':
		action_perform = request.POST.get('action_perform')
		message = request.POST.get('message')
		shared_aes_key = request.POST.get('shared_aes_key')
		if action_perform == 'rsa_encrypt':
			return HttpResponse(str(encrypt_RSA('public_key.der',str(message))))

@csrf_exempt
def aes(request):
	if request.method=='POST':
		action_perform = request.POST.get('action_perform')
		message = request.POST.get('message')
		shared_aes_key = request.POST.get('shared_aes_key')
		if action_perform == 'shared_key':
			return HttpResponse(shared_aes_encryption_generate())
		elif action_perform == 'aes_encrypt':
			Classobject = AESCipher(shared_aes_key)
			encrypted = Classobject.encrypt(str(message))
			print 'encryption'
			return HttpResponse(encrypted)
		elif action_perform == 'aes_decrypt':
			Classobject = AESCipher(shared_aes_key)
			print 'decryption'
			return HttpResponse(Classobject.decrypt(str(message)))
