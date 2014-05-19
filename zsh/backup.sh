#!/bin/sh
cp /etc/zshrc zshrc
cp /etc/zshenv zshenv
if [ -z "$(readlink $HOME/.zshrc)" ]; then
	cp $HOME/.zshrc zshrc-profile
fi
cp /usr/share/zsh/site-functions/_jarvis site-functions/_jarvis
cp /usr/share/zsh/site-functions/_msfconsole site-functions/_msfconsole
cp /usr/share/zsh/site-functions/_vmrun site-functions/_vmrun
