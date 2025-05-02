import socket

def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 65432))
    server_socket.listen()

    print("服务器已启动，等待连接...")
    conn, addr = server_socket.accept()
    with conn:
        print(f"已连接到 {addr}")
        with open('received_file.txt', 'wb') as f:
            while True:
                data = conn.recv(1024)
                if not data:
                    break
                f.write(data)
    print("文件接收完成")
    server_socket.close()

if __name__ == "__main__":
    start_server()