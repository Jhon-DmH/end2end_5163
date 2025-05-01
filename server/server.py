# file_server.py
from flask import Flask, request, jsonify
import os
import json
from controller.cyrptoController import CryptoController
from controller.fileController import FileController
from controller.userController import UserController

app = Flask(__name__)

userController = UserController()

@app.route('/login/auth', methods=['POST'])
def authenticate():
    data = request.get_json()  # Get JSON data from request
    username = data.get('username')
    password = data.get('password')
    result = userController.authenticate(username, password)
    return jsonify({'result':result})

@app.route('/login/regi', methods=['POST'])
def register_user():
    data = request.get_json()  # Get JSON data from request
    username = data.get('username')
    password = data.get('password')
    result,msg = userController.register_user(username, password)
    return jsonify({'result':result,'msg':msg})

@app.route('/file/list', methods=['GET'])
def getFileList():
    data = request.get_json()  # Get JSON data from request
    user = data.get('user')
    fileController=FileController(user)
    result = fileController.getFileList()
    return jsonify({'result':result})
@app.route('/file/dirlist', methods=['GET'])
def get_FileWithDirList():
    data = request.get_json()  # Get JSON data from request
    user = data.get('user')
    path = data.get('path')
    fileController=FileController(user)
    result = fileController.get_FileWithDirList(path)
    return jsonify({'result':result})
@app.route('/sendFile', methods=['POST'])
def saveFile():
    if not request.files:
        return jsonify({'error': 'No file part'}), 400
    fileData=request.files["file"]
    fileJson=json.loads(request.form["json"])
    file_path=fileJson['file_path']+'/'+fileJson['file_name']
    # If user does not select file, browser submits empty part
    if fileData:
        try:
            with open(file_path,'wb') as file:
                file.write(fileData.read())
            return jsonify({'success': 'Success!'}), 200
        except Exception as e:
            temp=e
            return jsonify({'error': 'Error while reading file'}), 400
@app.route('/getFile', methods=['get'])
def getFile():
    data = request.get_json()  # Get JSON data from request
    file_Path = data.get('file')
    fileData=[]
    try:
        with open(file_Path, 'rb') as file:
            fileData=file.read()
        return fileData, 200
    except Exception as e:
        temp = e
        return jsonify({'error': 'Error while reading file'}), 400
    return

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
