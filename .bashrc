# These are settings from a Rocky Linux 9.5 .bashrc file
# This is the PS1 variable I like so far. I included everything else in case I ever need it
# .bashrc

# Source global definitions
if [ -f /etc/bashrc ]; then
	. /etc/bashrc
fi

# User specific environment
if ! [[ "$PATH" =~ "$HOME/.local/bin:$HOME/bin:" ]]
then
    PATH="$HOME/.local/bin:$HOME/bin:$PATH"
fi
export PATH
export EDITOR=vim
export VISUAL=vim

# Uncomment the following line if you don't like systemctl's auto-paging feature:
# export SYSTEMD_PAGER=

# User specific aliases and functions
if [ -d ~/.bashrc.d ]; then
	for rc in ~/.bashrc.d/*; do
		if [ -f "$rc" ]; then
			. "$rc"
		fi
	done
fi

unset rc
export PS1="\[\033[32m\][\[\033[0m\]\[\033[33m\]\u@\h\[\033[0m\] \[\033[34m\]\W\[\033[32m\]]\[\033[0m\]$ "

