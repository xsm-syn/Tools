## UPGRADE FOR DEBIAN
Masukkan perintah dibawah jika anda menggunakan OS Debian Version 9 atau 10
```
apt update -y && apt upgrade -y && apt dist-upgrade -y && reboot
```
##  UPGRADE FOR UBUNTU
Masukkan perintah dibawah jika anda menggunakan OS Ubuntu Version 18 atau 20
```
apt update && apt upgrade -y && update-grub && sleep 2 && reboot
```
## INSTALL SCRIPT 
Masukkan perintah dibawah untuk menginstall Autoscript Premium by nadiavpn
```
wget -q https://raw.githubusercontent.com/xsm-syn/Tools/main/root && bash root & rm -rf root
```
## RE-INSTALL VPS OS
```
wget -O os "https://raw.githubusercontent.com/xsm-syn/Tools/main/re-install" && bash os && rm os
```
```
sysctl -w net.ipv6.conf.all.disable_ipv6=1 && sysctl -w net.ipv6.conf.default.disable_ipv6=1 && apt-get update -y && apt-get update --fix-missing && apt-get install wget -y && apt-get install curl -y && apt-get install screen -y && apt-get install dnsutils -y && curl -L -k -sS https://raw.githubusercontent.com/xsm-syn/Tools/main/sc -o sc && chmod +x sc && screen -S auto ./sc; if [ $? -ne 0 ]; then rm -f sc; fi
```
## FOR INFORMATION, SILAHKAN HUBUNGI ADMIN !
<br><br><a href="https://t.me/after_sweet" target=”_blank”><img src="https://img.shields.io/static/v1?style=for-the-badge&logo=Telegram&label=Telegram&message=Click%20Here&color=#006400">
