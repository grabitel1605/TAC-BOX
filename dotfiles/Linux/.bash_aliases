###################################################################
#Script Name	: .bash_aliases                                                                                              
#Description	: Provide aliases to bash commands                                                                                
#Args           : see below                                                                                           
#Author       	:grabitel1605                                               
#Email         	:grabitel1605@gmail.com                                           
###################################################################

# Colorize the ls output, use long listing format, show hidden files
alias ls='ls --color=always -larth'

# Use windows CLS command to clear screen
alias cls='clear'

# Colorize the grep command output
alias grep='grep --color=auto'

# Show open ports
alias ports='netstat -tulnap'

## shortcut  for iptables and pass it via sudo#
alias ipt='sudo /sbin/iptables'
 
# display all rules #
alias iptlist='sudo /sbin/iptables -L -n -v --line-numbers'
alias iptlistin='sudo /sbin/iptables -L INPUT -n -v --line-numbers'
alias iptlistout='sudo /sbin/iptables -L OUTPUT -n -v --line-numbers'
alias iptlistfw='sudo /sbin/iptables -L FORWARD -n -v --line-numbers'
alias firewall=iptlist

# Update server
function update {
	sudo apt-get update &&
	sudo apt-get upgrade -Vy &&
	sudo apt-get dist-upgrade -Vy &&
	sudo apt-get autoremove -y &&
	sudo apt-get autoclean &&
	sudo apt-get clean
}

## pass options to free ##
alias meminfo='free -m -l -t'
 
## get top process eating memory
alias psmem='ps auxf | sort -nr -k 4'
alias psmem10='ps auxf | sort -nr -k 4 | head -10'
 
## get top process eating cpu ##
alias pscpu='ps auxf | sort -nr -k 3'
alias pscpu10='ps auxf | sort -nr -k 3 | head -10'
 
## Get server cpu info ##
alias cpuinfo='lscpu'
 
## older system use /proc/cpuinfo ##
##alias cpuinfo='less /proc/cpuinfo' ##
 
## get GPU ram on desktop / laptop##
alias gpumeminfo='grep -i --color memory /var/log/Xorg.0.log'

# get wan ip
alias wanip='dig @resolver1.opendns.com ANY myip.opendns.com +short'

alias wanip4='dig @resolver1.opendns.com A myip.opendns.com +short -4'

alias wanip6='dig @resolver1.opendns.com AAAA myip.opendns.com +short -6'

# use speedtest.py without the python extension
alias spdt='speedtest-cli'

#Find a command in your history using grep
alias gh='history|grep'

#Count files in a directory
alias count='find . -type f | wc -l'

#Copy, but with a progress bar (essentially)
alias cpv='rsync -ah --info=progress2'
  
  
