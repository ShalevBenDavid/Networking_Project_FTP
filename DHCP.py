import socket



ip = "127.0.0.1"
port = 100

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((ip, port))
server.listen(1)

while True:
    client, address = server.accept()
    print("Connected Successfully -", address)
    query = client.recv(1024)
    query = query.decode("utf-8")

    client.send("Your IP is : 184.10.10.50".encode())


    print(query)
    client.close()
