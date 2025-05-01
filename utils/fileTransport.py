import json
import os
from tkinter import messagebox

import requests


# SERVER 的 URL， 要和server 终端中输出的一模一样！
SERVER_URL = 'http://192.168.10.3:5000/'
class FileTransport:


    # 把本地的存服务器上
    # file_paht: 本地文件路径
    # dest_path: 服务目标文件夹路径
    # 列：sendFile('D:/CODE/5163/upload_file/test1.txt','D:/CODE/5163/controller/keys')
    # 把 D:/CODE/5163/upload_file/test1.txt 写到 D:/CODE/5163/controller/keys 里
    def sendFile(self,file_path,dest_path):
        file_name=os.path.basename(file_path)

        payload = {'file_path': dest_path,'file_name':file_name}
        files = {
            'json': (None, json.dumps(payload), 'application/json'),
            'file': (os.path.basename(file_path), open(file_path, 'rb'), 'application/octet-stream')
        }

        # Make the POST request
        response = requests.post(f'{SERVER_URL}/sendFile',files=files)
        # Check for HTTP errors
        response.raise_for_status()
        return

    # 把服务器上的的存本地
    # file_paht: 服务器文件路径
    # dest_path: 本地目标文件夹路径
    # 列：sendFile('D:/CODE/5163/upload_file/test1.txt','D:/CODE/5163/controller/keys')
    # 把 D:/CODE/5163/upload_file/test1.txt 写到 D:/CODE/5163/controller/keys 里
    def saveFile(self, file_path,dest_path):
        file_name = os.path.basename(file_path)
        # Get the file
        payload = {'file': file_path}
        # Make the POST request
        response = requests.get(f'{SERVER_URL}/getFile', json=payload)
        # Check for HTTP errors
        response.raise_for_status()
        data = response.content
        dest_file = dest_path + '/' + file_name
        with open(dest_file, 'wb') as file:
            file.write(data)
        return

def main():
    temp=FileTransport()
    #temp.sendFile('D:/CODE/5163/upload_file/test1.txt','D:/CODE/5163/controller/keys')
    temp.saveFile('D:/CODE/5163/controller/keys/test1.txt','D:/CODE/5163/data')


if __name__ == "__main__":
    main()