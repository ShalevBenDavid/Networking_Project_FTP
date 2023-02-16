from ftplib import FTP
host="192.168.56.1"
user= "shuster"
password="12345"

with FTP(host) as ftp:
    ftp.login(user=user, password=password)
    print(ftp.getwelcome())


    # with open(('test.txt','wb')) as f:
    #     ftp.retrbinary("RETR"+ "mytest.txt", f.write,1024)


    with open('myupload.txt','rb') as f:
        ftp.storbinary('STOR'+ 'upload.txt',f)

    ftp.quit()




