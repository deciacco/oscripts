!#/bin/bash

sudo apt update

#theme
sudo add-apt-repository ppa:daniruiz/flat-remix
sudo apt update
sudo apt install flat-remix
sudo apt install flat-remix-gtk

sudo apt install geany
sudo apt install geany-plugins

sudo apt install tilix

#brave
sudo apt install apt-transport-https curl
sudo curl -fsSLo /usr/share/keyrings/brave-browser-archive-keyring.gpg https://brave-browser-apt-release.s3.brave.com/brave-browser-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/brave-browser-archive-keyring.gpg arch=amd64] https://brave-browser-apt-release.s3.brave.com/ stable main"|sudo tee /etc/apt/sources.list.d/brave-browser-release.list
sudo apt update
sudo apt install brave-browser

#mouse touchpad stuff
#!/bin/bash
synclient RightButtonAreaLeft=0
synclient RightButtonAreaTop=0
synclient HorizHysteresis=0
synclient VertHysteresis=0
synclient VertEdgeScroll=0
synclient PalmDetect=1
synclient VertScrollDelta=-30

#make permanent create an edit this file
#https://wiki.archlinux.org/title/Touchpad_Synaptics#Synclient
#/usr/share/X11/xorg.conf.d/
#remove hysteresis and right-click area of touchpad
#Section "InputClass"
#        Identifier "Disable Right Click"
#        MatchDriver "synaptics"
#        Option "SoftButtonAreas" "0 0 0 0 0 0 0 0"
#        Option "HorizHysteresis" "0"
#        Opiton "VertHysteresis" "0"
#EndSection

sudo apt install hstr

sudo apt install git -y
sudo apt install zsh -y
sh -c "$(curl -fsSL https://raw.github.com/ohmyzsh/ohmyzsh/master/tools/install.sh)"

git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ${ZSH_CUSTOM:-$HOME/.oh-my-zsh/custom}/themes/powerlevel10k
git clone https://github.com/zsh-users/zsh-autosuggestions.git $ZSH_CUSTOM/plugins/zsh-autosuggestions 
git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $ZSH_CUSTOM/plugins/zsh-syntax-highlighting

sudo apt install python3 python3-pip -y

curl -fsSL https://deb.nodesource.com/setup_16.x | sudo -E bash -
sudo apt-get install -y nodejs
sudo npm install nativefier -g

pip install mkdocs
pip install mkdocs-macros-plugin
pip install mkdocs-material

sudo curl -o /usr/share/keyrings/syncthing-archive-keyring.gpg https://syncthing.net/release-key.gpg
echo "deb [signed-by=/usr/share/keyrings/syncthing-archive-keyring.gpg] https://apt.syncthing.net/ syncthing stable" | sudo tee /etc/apt/sources.list.d/syncthing.list
sudo apt-get update
sudo apt install syncthing

sudo apt install remmina



