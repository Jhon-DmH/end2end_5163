import socket

def send_file():
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('localhost', 65432))

    with open('file_to_send.txt', 'rb') as f:
        data = f.read(1024)
        while data:
            client_socket.sendall(data)
            data = f.read(1024)
    print("文件发送完成")
    client_socket.close()

if __name__ == "__main__":
    send_file()