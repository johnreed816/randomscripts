#!/bin/bash
#
# PCI Complaince script
# 
# Written by John Reed
#
# RHEL 5
#
# 10/25/2012

###########################################################
function AdditionalProcessHardening 
###########################################################
{
    # Requirement 1.7.1 - Restrict core dumps
    echo "setting restriction on core dumps"
    echo "*        hard   core        0" >> /etc/security/limits.conf
    echo "fs.suid.dumpable = 0" >> /etc/sysctl.conf

    # Requirement 1.7.2 - Configure ExecShield 
    echo "configuring kenel ExecShield"
    if [[ $(grep -m 1 "kernel.exec-shield" /etc/sysctl.conf) ]]
    then
        if [[ $(grep -m 1 "kernel.exec-shield" /etc/sysctl.conf | grep 0) ]]
        then 
            sed -i 'kernel.exec-shield/d' /etc/sysctl.conf  
            echo "kernel.exec-shield = 1" >> /etc/sysctl.conf  
        fi
    else
        echo "kernel.exec-shield = 1" >> /etc/sysctl.conf
    fi

    # Requirement 1.7.3 - Enable randomized virtual memory region placement 
    echo "enabling randomized virtual memory region placement"
    if [[ $(grep -m 1 "kernel.randomize_va_space" /etc/sysctl.conf) ]]
    then
        if [[ $(grep -m 1 "kernel.randomize_va_space" /etc/sysctl.conf | grep 0) ]]
        then
            sed -i 'kernel.randomize_va_space/d' /etc/sysctl.conf 
            echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf 
        fi
    else
        echo "kernel.randomize_va_space = 1" >> /etc/sysctl.conf
    fi

    # Requirement 1.7.4 - Enable XD/NX support on 32-bit x86 systems
    echo "checking for kernel PAE support"
    if ! [[ $(yum list kernel-PAE | grep installed) ]]
    then
        echo "installing kernel PAE"
        yum -y install kernel-PAE    
    fi
}

##########################################################
function LoggingAndAuditing 
##########################################################
{
    # Configure syslog
    echo "***** Configuration for logging and auditing *****"
    echo "configuring rsyslog"
    if ! [[ $(yum list rsyslog | grep installed) ]]
    then
        yum -y install rsyslog
    fi
    if ! [[ $(/sbin/chkconfig --list rsyslog | grep on) ]] 
    then
        /sbin/chkconfig rsyslog off
    fi 
    # just making sure...
    if [[ $(/sbin/chkconfig --list syslog | grep on) ]]
    then
        /sbin/chkconfig syslog off
    fi 
               
    echo "setting permissions for /var/log/messages"
    if ! [ -e /var/log/messages ]
    then
        touch /var/log/messages
    fi
    chown root:root /var/log/messages  
    chmod og-rwx /var/log/messages
    echo "creating and setting permissions for /var/log/kern.log"
    if ! [ -e /var/log/kern.log ]
    then
        touch /var/log/kern.log 
    fi
    chown root:root /var/log/kern.log
    chmod og-rwx /var/log/kern.log
    echo "creating and setting permissions for /var/log/daemon.log"
    if ! [ -e /var/log/daemon.log ]
    then
        touch /var/log/daemon.log 
    fi
    chown root:root /var/log/daemon.log
    chmod og-rwx /var/log/daemon.log
    echo "creating and setting permissions for /var/log/syslog"
    if ! [ -e /var/log/syslog ]
    then
        touch /var/log/syslog 
    fi
    chown root:root /var/log/syslog
    chmod og-rwx /var/log/syslog

    echo "Configuring system accounting"
    if ! [[ $(/sbin/chkconfig --list auditd | grep on) ]]
    then
        /sbin/chkconfig auditd on
    fi

    echo "creating temporary auditd configuration file"
    cp /etc/audit/auditd.conf /etc/audit/auditd.conf.tmp
    echo "checking for audit log full settings"
    if [[ $(grep -m 1 space_left_action /etc/audit/auditd.conf | grep -v admin) ]]
    then
        sed -i 's/space_left_action =.*/space_left_action = email/g' /etc/audit/auditd.conf
    else
        echo "space_left_action =  email" >> /etc/audit/auditd.conf
    fi
    echo "checking admin log full settings"
    if [[ $(grep -m 1 admin_space_left_action /etc/audit/auditd.conf) ]]
    then
        sed -i 's/admin_space_left_action =.*/admin_space_left_action = email/g' /etc/audit/auditd.conf 
    else
        echo "admin_space_left_action = email" >> /etc/audit/auditd.conf
    fi

    echo "checking log file action"
    if [[ $(grep -m 1 max_log_file_action /etc/audit/auditd.conf) ]] 
    then
        echo "setting log file action to keep"
        sed -i 's/max_log_file_action =.*/max_log_file_action = keep_logs/g' /etc/audit/auditd.conf 
    else
        echo "max_log_file_action = keep_logs" >> /etc/audit/auditd.conf
    fi
    #if [[ $(grep -m 1 audit /etc/grub.conf) ]]
    #then
    #    echo "setting audit to true in grub.conf"
    #    sed -i 's/audit=.*/audit=1/g' /etc/grub.conf 
    #else
    #    echo "audit=1" > /etc/grub.conf
    #fi 

    echo "creating temporary audit rules configuration file"
    cp /etc/audit/audit.rules /etc/audit/audit.rules.tmp
    echo "checking auditing rules"
    if ! [[ $(grep -m 1 time-change /etc/audit/audit.rules) ]] 
    then
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "setting audit rules for 32 bit system" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k timechange" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
            echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
        else
            echo "setting audit rules for 64 bit system"
            echo "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b64 -S clock_settime -k time-change" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S clock_settime -k time-change" >> /etc/audit/audit.rules
            echo "-w /etc/localtime -p wa -k time-change" >> /etc/audit/audit.rules
        fi
    fi
    if ! [[ $(grep -m 1 identity /etc/audit/audit.rules) ]]
    then
        echo "-w /etc/group -p wa -k identity" >> /etc/audit/audit.rules
        echo "-w /etc/passwd -p wa -k identity" >> /etc/audit/audit.rules
        echo "-w /etc/gshadow -p wa -k identity" >> /etc/audit/audit.rules
        echo "-w /etc/shadow -p wa -k identity" >> /etc/audit/audit.rules
    fi
    if ! [[ $(grep -m 1 system-locale /etc/audit/audit.rules) ]]
    then
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules 
            echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
        else
            echo "-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
            echo "-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/issue -p wa -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/issue.net -p wa -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/hosts -p wa -k system-locale" >> /etc/audit/audit.rules
            echo "-w /etc/sysconfig/network -p wa -k system-locale" >> /etc/audit/audit.rules
        fi
    fi
    if ! [[ $(grep -m 1 MAC-policy /etc/audit/audit.rules) ]]
    then
        echo "-w /etc/selinux/ -p wa -k MAC-policy" >> /etc/audit/audit.rules 
    fi
    if ! [[ $(grep -m 1 logins /etc/audit/audit.rules) ]]
    then
        echo "-w /var/log/faillog -p wa -k logins" >> /etc/audit/audit.rules 
        echo "-w /var/log/lastlog -p wa -k logins" >> /etc/audit/audit.rules 
        echo "-w /var/log/tallylog -p wa -k logins" >> /etc/audit/audit.rules 
        echo "-w /var/log/btmp -p wa -k session" >> /etc/audit/audit.rules 
    fi
    if ! [[ $(grep -m 1 perm_mod /etc/audit/audit.rules) ]]
    then
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
            echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
        else
            echo "-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules  
            echo "-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
            echo "-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
            echo "-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules 
            echo "-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod" >> /etc/audit/audit.rules
        fi
    fi
    if ! [[ $(grep -m 1 access /etc/audit/audit.rules) ]]
    then 
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
        else
            echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access" >> /etc/audit/audit.rules
        fi
    fi
    if ! [[ $(grep -m 1 mounts /etc/audit/audit.rules) ]]
    then
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules 
            echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules 
        else
            echo "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts" >> /etc/audit/audit.rules 
        fi
    fi
    if ! [[ $(grep -m 1 deleted /etc/audit/audit.rules) ]]
    then
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F 
auid>=500 -F auid!=4294967295 -k delete" > /etc/audit/audit.rules
        else
            echo "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
            echo "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete" >> /etc/audit/audit.rules
        fi
    fi
    if ! [[ $(grep -m 1 scope /etc/audit/audit.rules) ]]
    then 
        echo "-w /etc/sudoers -p wa -k scope" >> /etc/audit/audit.rules
    fi
    if ! [[ $(grep -m 1 actions /etc/audit/audit.rules) ]]
    then 
        echo "-w /var/log/sudo.log -p wa -k actions" >> /etc/audit/audit.rules
    fi
    if ! [[ $(grep -m 1 modules /etc/audit/audit.rules) ]]
    then 
        echo "-w /sbin/insmod -p wa -k actions" >> /etc/audit/audit.rules
        echo "-w /sbin/rmmod -p wa -k actions" >> /etc/audit/audit.rules
        echo "-w /sbin/modprobe -p wa -k actions" >> /etc/audit/audit.rules
        if [ `getconf LONG_BIT` = "32" ]
        then
            echo "-a always,exit arch=b32 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
        else
            echo "-a always,exit arch=b64 -S init_module -S delete_module -k modules" >> /etc/audit/audit.rules
        fi
    fi
    echo "checking if audit configuration immutable"
    if ! [[ $(grep -m 1 "^-e 2" /etc/audit/audit.rules) ]]
    then 
        echo "setting audit configuration to immutable"
        echo "-e 2" >> /etc/audit/audit.rules
    fi
    echo "reloading the auditd configuration file with new changes"
    if ! [[ $(/etc/init.d/auditd restart) ]]
    then
        echo "something went wrong... reloading old configuration..."
        # log this error to a file
        mv /etc/audit/auditd.conf.tmp /etc/audit/auditd.conf
        mv /etc/audit/audit.rules.tmp /etc/audit/audit.rules
        /sbin/service auditd reload
    else
        echo "cleaning up temporary files"
       rm /etc/audit/auditd.conf.tmp
       rm /etc/audit/audit.rules.tmp
    fi
}

#######################################################
function NetworkConfiguration 
#######################################################
{
    declare -a MODPROBEDISABLE=('dccp'
                                'sctp' 
                                'rds' 
                                'tipc'); 

    # these may already be set, but do it anyway
    echo "disabling IPv4 Forwarding"
    /sbin/sysctl -w net.ipv4.ip_forward=0
    echo "disabling IPv4 send packet redirects"
    /sbin/sysctl -w net.ipv4.conf.all.send_redirects=0
    echo "disabling IPv4 source routed packet acceptance"
    /sbin/sysctl -w net.ipv4.conf.all.accept_source_route=0   
    /sbin/sysctl -w net.ipv4.conf.default.accept_source_route=0   
    # log suspicious packets
    echo "enabling suspicious packet logging"
    /sbin/sysctl -w net.ipv4.conf.all.log_martians=1
    # ignore broadcast requests
    echo "enabling ignore broadcast requests"
    /sbin/sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
    # enable bad error message protection
    echo "enabling bad error message protection"
    /sbin/sysctl -w net.ipv4.icmp_ignore_bogus_error_responses=1
    # enable source route validation
    echo "enabling source route validation"
    /sbin/sysctl -w net.ipv4.conf.all.rp_filter=1
    /sbin/sysctl -w net.ipv4.conf.default.rp_filter=1
    # enable SYN cookies
    echo "enabling TCP SYN cookies"
    /sbin/sysctl -w net.ipv4.tcp_syncookies=1
    # flush routes to make changes
    echo "flushing routes..."
    /sbin/sysctl -w net.ipv4.route.flush=1

    # disable IPv6
    #echo "checking if IPv6 is enabled."
    #if [[ $(grep -m 1 disable=0 /etc/modprobe.conf |grep ipv6) ]]
    #then
    #    echo "disabling IPv6"
    #    echo options ipv6 "disable=1" >> /etc/modprobe.conf    
    #fi

    # set the permissions for hosts.allow and hosts.deny
    echo "set the permissions for the hosts.allow and hosts.deny files"
    /bin/chmod 644 /etc/hosts.allow
    /bin/chmod 644 /etc/hosts.deny

    for mod in "${MODPROBEDISABLE[@]}"
    do
        echo "checking for kernel module ${mod}"
        if ! [[ $(grep -m 1 ${mod} /etc/modprobe.conf | grep true) ]]
        then
            echo "disabling the loading of kernel module: ${mod}"
            echo "install ${mod} /bin/true" >> /etc/modprobe.conf 
        fi
    done
}

#########################################################
function ConfigurePAM 
#########################################################
{
    echo "configuring user password requirements"
    if [[ $(grep -m 1 pam_cracklib /etc/pam.d/system-auth) ]]
    then 
         sed -i "s/^password    requisite      pam_cracklib.so try_first_pass retry=3/password    required     pam_cracklib.so try_first_pass retry=3 minlen=14,dcredit=-1,ucredit=-1,ocredit=-1 lcredit=01/g" /etc/pam.d/system-auth   
    fi
  
    echo "checking user password strength password"
    if ! [[ $(grep -m 1 pam_passwdqc /etc/pam.d/system-auth | grep "min=disabled,disabled") ]]
    then
        echo "configuring user password strength policy"
        echo "password    requisite     pam_passwdqc.so min=disabled,disabled,16,12,8"  /etc/pam.d/system_auth

    fi

    echo "checking password reuse policy"
    if ! [[ $(grep -m 1 pam_unix.o /etc/pam.d/system-auth | grep "remember=") ]]
    then 
        echo "configuring password reuse policy"
        echo "password    sufficient    pam_unix.o remember=5"  /etc/pam.d/system_auth
    fi
}

############################################################
function RemoveLegacyServices 
############################################################
{
    declare -a YUMDELETE=('telnet-server'
                          'telnet'
                          'rsh-server'
                          'rsh'
                          'ypbind'
                          'ypserv'
                          'tftp'
                          'tftp-server'
                          'talk'
                          'talk-server'
                          'xinetd'
                          'dhcp'
                          'openldap-servers'
                          'bind'
                          'vsftpd'
                          'dovecot'
                          'samba'
                          'squid'
                          'net-snmp'
                          'tcp_wrappers'
                          'pam_ccreds'
                          'nfs-utils');

    declare -a CHKCONFIGOFF=('rhnsd',
                             'yum-updatesd'
                             'setroubleshoot'
                             'mctrans'
                             'chargen-dgram'
                             'chargen-stream'
                             'daytime-dgram'
                             'daytime-stream'
                             'echo-dgram'
                             'echo-stream'
                             'tcpmux-server'
                             'avahi-daemon'
                             'cups'
                             'nfslock'
                             'rpcgssd'
                             'rpcidmapd'
                             'portmap'
                             'syslog');

    echo "***** Removing Legacy services *****"
    for pkg in "${YUMDELETE[@]}"
    do
        echo "checking if ${pkg} is installed"
        if [[ $(yum list ${pkg} | grep installed) ]]
        then
            echo "removing ${pkg}"
            yum -y erase ${pkg}
        fi
    done
    for cfg in "${CHKCONFIGOFF[@]}"
    do
        echo "stopping ${cfg} service"
        /sbin/chkconfig ${cfg} off
    done
}

#########################################################
function SecureBootSettings 
#########################################################
{
    # Requirement 1.6.1 - Set user/group for grub.conf
    echo "setting user and group for /etc/grub.conf"
    chown root:root /etc/grub.conf

    # Requirement 1.6.2 - Set permissions on grub.conf
    echo "setting permissions for /etc/grub.conf"
    chmod og-rwx /etc/grub.conf

    if ! [[ $(grep -m 1 sulogin /etc/inittab) ]]
    then
        echo "~:S:wait:/sbin/sulogin" >> /etc/inittab 
    fi

    # Requirement 1.6.5 - Disable interactive boot
    echo "checking interactive boot settings"
    if [[ $(grep -m 1 PROMPT=yes /etc/sysconfig/init) ]]
    then
        echo "disabling interactive boot"
        sed -i 's/PROMPT=yes/PROMPT=no/g' /etc/sysconfig/init 
    fi
} 

#########################################################
function SElinuxConfiguration 
#########################################################
{
    # Requirement 1.5 - SELinux shit
    echo "checking if SELinux is enabled"
    if ! [[ $(grep -m 1 selinux /etc/grub.conf) ]] 
    then
        echo "enabling SELinux"
        echo "selinux=1" >> /etc/grub.conf
    elif [[ $(grep -m 1 selinux=0 /etc/grub.conf) ]]
    then
        echo "enabling SELinux"
        sed -i 's/selinux=0/selinux=1/g' /etc/grub.conf 
    fi

    echo "checking SELinux configuration"
    if ! [[ $(grep -m 1 enforcing /etc/grub.conf) ]]
    then
        echo "setting enforcing of SELinux to true"
        echo "enforcing=1" >> /etc/grub.conf
    elif [[ $(grep -m 1 enforcing=0 /etc/grub.conf) ]]
    then
        sed -i 's/enforcing=0/enforcing=1/g' /etc/grub.conf 
    fi

    # Requirement 1.5.2 - Set SELinux state
    echo "checking SELinux state"
    if [[ $(grep -m 1 SELINUX=disabled /etc/selinux/config) ]]
    then
        echo "setting SELinux to enforcing"
        sed -i 's/SELINUX=disabled/SELINUX=enforcing/g' /etc/selinux/config 
    elif [[ $(grep -m 1 SELINUX=permissive /etc/selinux/config) ]]
    then
        sed -i 's/SELINUX=permissive/SELINUX=enforcing/g' /etc/selinux/config 
    fi

    # Requirement 1.5.3 - Set SELinux policy
    echo "checking SELinux policy"
    if [[ $(grep -m 1 SELINUXTYPE=strict /etc/selinux/config) ]]
    then
        echo "setting SELinux to targeted"
        sed -i 's/SELINUXTYPE=strict/SELINUXTYPE=targeted/g' /etc/selinux/config 
    fi

    # Requirement 1.5.4 - Remove SETroubleshoot
    echo "checking for SETroubleshoot services"
    if ! [[ $(/sbin/chkconfig --list setroubleshoot) ]] 
    then
        echo "setting setroubleshoot to off"
        /sbin/chkconfig setroubleshoot off     
    fi

    # Requirement 1.5.5 - Disable MCS Translation Service
    echo "checking for MCS Translation services"
    if ! [[ $(/sbin/chkconfig --list mctrans) ]] 
    then
        echo "setting mctranas to off"
        /sbin/chkconfig mctrans off     
    fi
}

function SoftwareUpdateConfiguration {
    # Requirement 1.3.3 - gpgcheck is globally activated
    echo "checking if gpgcheck is globally activated"
    if [[ $(grep -m 1 gpgcheck=0 /etc/yum.conf) ]];
    then
        echo "setting gpgcheck to global"
        sed -i 's/gpcheck=0/gpgcheck=1/g' /etc/yum.conf 
    fi

    # Requirement 1.3.6 - Update software packages
    yum -y update

    # Set prelinking to no
    echo "checking if prelinking is set"
    if [[ $(grep -m 1 PRELINKING=yes /etc/sysconfig/prelink) ]];
    then
       echo "setting prelinking to no"
       sed -i 's/PRELINKING=yes/PRELINKING=no/g' /etc/sysconfig/prelink 
       /usr/bin/prelink -ua
    fi
    # Requirement 1.4.1 - Install AIDE 
    echo "checking if aide is installed"
    if ! [[ $(yum list aide | grep installed) ]]
    then
        echo "Installing aide"
        yum -y install aide
    fi

    # Requirement 1.4.2 - Implement periodic execution of file integrity
    echo "checking aide cron settings"
    if ! [[ $(grep -m 1 /usr/bin/aide /etc/crontab) ]] 
    then
        echo "adding aide file integrity check to crontab"
        echo "0 5 * * * /usr/bin/aide -check" >> /etc/crontab
    fi
}

#######################################################
function SpecialServices 
#######################################################
{
    # set daemon umask
    echo "checking daemon file permissions" 
    if ! [[ $(grep -m 1  umask /etc/sysconfig/init |grep 027 ) ]]
    then
        echo "setting umask for /etc/sysconfig/init"
        echo "umask 027" >> /etc/sysconfig/init
    fi

    # this should be case by case
    # remove X Windows
    echo "checking if X Windows is installed"
    if [[ $(yum grouplist "X Window System") ]]
    then
        echo "removing X Windows System"
        yum -y groupremove "X Window System"
    fi
    
    echo "checking NTP settings"
    if ! [[ $(grep "restrict default" /etc/ntp.conf) ]]
    then
        echo "setting NTP settings"
        echo "restrict default" >> /etc/ntp.conf     
        echo "restrict -6 default" >> /etc/ntp.conf     
    fi
    if ! [[ $(grep "restrict -6 default" /etc/ntp.conf) ]]
        echo "setting NTP settings"
    then
        echo "restrict -6 default" >> /etc/ntp.conf
    fi
}

########################################################
function SystemAccessAndAuth 
########################################################
{
    echo "configuring file permissions for cron files"
    if [ -e /etc/anacrontab ] 
    then
        chown root:root /etc/anacrontab
        chmod og-rwx /etc/anacrontab
    fi
    if [ -e /etc/crontab ] 
    then
        chown root:root /etc/crontab
        chmod og-rwx /etc/crontab
    fi
    if [ -e /etc/cron.hourly ] 
    then
        chown root:root /etc/cron.hourly
        chmod og-rwx /etc/cron.hourly
    fi
    if [ -e /etc/cron.daily ] 
    then
        chown root:root /etc/cron.daily
        chmod og-rwx /etc/cron.daily
    fi
    if [ -e /etc/cron.weekly ] 
    then
        chown root:root /etc/cron.weekly
        chmod og-rwx /etc/cron.weekly
    fi
    if [ -e /etc/cron.monthly ] 
    then
        chown root:root /etc/cron.monthly
        chmod og-rwx /etc/cron.monthly
    fi
    if [ -e /etc/cron.d ] 
    then
        chown root:root /etc/cron.d
        chmod og-rwx /etc/cron.d
    fi
    if [ -e /etc/at.deny ] 
    then
        rm /etc/at.deny
        if ! [ -e /etc/at.allow ]
        then
            touch /etc/at.allow
        fi
        chown root:root /etc/at.allow
        chmod og-rwx /etc/at.allow
    fi
    if [ -e /etc/cron.deny ]
    then 
        rm /etc/cron.deny    
        if ! [ -e /etc/cron.allow ]
        then
            touch /etc/cron.allow
        fi
        chown root:root /etc/cron.allow
        chmod og-rwx /etc/cron.allow
    fi 

    yum -y install openssh-server
    /etc/init.d/sshd start

    echo "configuring ssh"
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.tmp
    echo "setting permissions on /etc/ssh/sshd_config"
    chown root:root /etc/ssh/sshd_config
    chmod 644 /etc/ssh/sshd_config

    echo "checking log level settings"
    if ! [[ $(grep -m 1 "^LogLevel VERBOSE" /etc/ssh/sshd_config) ]]
    then
        echo "setting log level to verbose"
        sed -i 's/#LogLevel INFO/LogLevel VERBOSE/g' /etc/ssh/sshd_config 
    fi

    echo "checking X11 Forwarding settings"
    if ! [[ $(grep -m 1 "^X11Forwarding no" /etc/ssh/sshd_config) ]]
    then
        echo "disabling X11 Forwarding"
        sed -i "s/^X11Forwarding yes/#X11Forwarding yes/g" /etc/ssh/sshd_config 
        sed -i "s/#X11Forwarding no/X11Forwarding no/g" /etc/ssh/sshd_config 
    fi 

    echo "checking maximum authentication attempts setting"
    if [[ $(grep -m 1 "#MaxAuthTries" /etc/ssh/sshd_config) ]] 
    then
        echo "setting SSH max tries to 4"
        sed -i "s/#MaxAuthTries/MaxAuthTries/g" /etc/ssh/sshd_config 
    fi  
    if ! [[ $(grep -m 1 "^MaxAuthTries 4" /etc/ssh/sshd_confg) ]]
    then
        echo "setting SSH max tries to 4"
        sed -i "/^MaxAuthTries 4/d" /etc/ssh/sshd_config
        echo "MaxAuthTries 4" >> /etc/ssh/sshd_config
    fi

    echo "checking remote host authentication settings"
    if [[ $(grep -m 1 "#IgnoreRhosts no" /etc/ssh/sshd_config) ]]
    then
        echo "disabling using rhosts files for ssh authentication" 
        sed -i "s/#IgnoreRhosts/IgnoreRhosts/g" /etc/ssh/sshd_config
    fi
    if ! [[ $(grep -m 1 "^IgnoreRhosts" /etc/ssh/sshd_config) ]]
    then
        echo "disabling using rhosts files for ssh authentication" 
        echo "IgnoreRhosts yes" >> /etc/ssh/sshd_config
    fi
    
    echo "checking ssh host based authentication settings" 
    if [[ $(grep -m 1 "#HostbasedAuthentication" /etc/ssh/sshd_config) ]]
    then
        echo "disabling ssh host based authentication"
        sed -i "s/#HostbasedAuthentication/HostbasedAuthentication/g" /etc/ssh/sshd_config
    fi
    if ! [[ $(grep -m 1 "^HostbasedAuthentication no" /etc/ssh/sshd_config) ]]
    then
        echo "disabling ssh host based authentication"
        echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
    fi

    #echo "checking root login settings"
    #if [[ $(grep -m 1 "#PermitRootLogin" /etc/ssh/sshd_config) ]]
    #then
    #    echo "disabling remote root login"
    #    sed -i "s/#PermitRootLogin yes/PermitRootLogin no/g" /etc/ssh/sshd_config
    #fi

    #if ! [[ $(grep -m 1 "^PermitRootLogin" /etc/ssh/sshd_config) ]]
    #then
    #    echo "disabling remote root login"
    #    echo "PermitRootLogin no" >> /etc/ssh/sshd_config
    #fi

    echo "checking ssh password settings"
    if [[ $(grep -m 1 "#PermitEmptyPasswords" /etc/ssh/sshd_config) ]]
    then
        echo "disabling empty SSH passwords"
        sed -i "s/#PermitEmptyPasswords/PermitEmptyPasswords/g" /etc/ssh/sshd_config
    fi

    echo "checkign user environment configuration"
    if [[ $(grep -m 1 "#PermitUserEnvironment" /etc/ssh/sshd_config) ]]
    then
        echo "disabling users setting environment options"
        sed -i "s/#PermitUserEnvironment/PermitUserEnvironment/g" /etc/ssh/sshd_config
    fi

    echo "checking ssh crypto configuration"
    if ! [[ $(grep -m 1 Ciphers /etc/ssh/sshd_config | grep aes) ]]
    then
        echo "forcing ssh to only use approved crypto in counter mode"
        echo "Ciphers aes128-ctr,aes192-ctr,aes256-ctr" >> /etc/ssh/sshd_config 
    fi

    echo "checking ssh client alive interval"
    if [[ $(grep -m 1 "#ClientAliveInterval" /etc/ssh/sshd_config) ]]
    then
        echo "setting client alive interval to 5 minutes"
        sed -i "s/#ClientAliveInterval 0/ClientAliveInterval 300/g" /etc/ssh/sshd_config
    fi

    echo "checking ssh client alive max configuration"
    if [[ $(grep -m 1 "#ClientAliveCountMax" /etc/ssh/sshd_config) ]]
    then
        echo "setting client alive count max to zero"
        sed -i "s/#ClientAliveCountMax 3/ClientAliveCountMax 0/g" /etc/ssh/sshd_config
    fi

    # reload configuration file
    echo "reloading sshd configuration file"
    if ! [[ $(/sbin/service sshd reload) ]]
    then
        echo "reloading failed! Restoring ssh configuration"
        mv /etc/ssh/sshd_config.tmp /etc/ssh/sshd_config
    else
        echo "cleaning up temp files"
        rm /etc/ssh/sshd_config.tmp
    fi
    echo "ssh configuration complete"
}

##########################################################
function SystemMaintenance 
##########################################################
{
    # file permissions  - these are probably set by default
    # but doesn't hurt to do it anyway
    echo "configuring /etc/passwd"
    chmod 644 /etc/passwd
    chown root:root /etc/passwd

    echo "configuring /etc/shadow"
    chmod 400 /etc/shadow
    chown root:root /etc/shadow

    echo "configuring /etc/gshadow"
    chmod 400 /etc/gshadow
    chown root:root /etc/gshadow

    echo "configuring /etc/group"
    chmod 644 /etc/group
    chown root:root /etc/group
    # file ownership - these are probably set by default
    # but doesn't hurt to do it anyway
}

#########################################################
function ConfiguringUserAccounts {
#########################################################
    echo "setting password expiration to 90 days"
    sed -i "s/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/g"  /etc/login.defs
    sed -i "s/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/g"  /etc/login.defs
    echo "UMASK=077" >> /etc/bashrc
    echo "UMASK=077" >> /etc/profile
    /usr/sbin/useradd -D -f 35
} 

#########################################################
function SetWarningBanner 
#########################################################
{
    echo "adding warning banners"
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/motd
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue
    echo "Authorized uses only. All activity may be monitored and reported." > /etc/issue.net

    echo "configuring /etc/motd"
    echo "configuring /etc/issue"
    echo "configuring /etc/issue.net"
    chown root:root /etc/motd
    chown root:root /etc/issue
    chown root:root /etc/issue.net
    chmod 644 /etc/motd
    chmod 644 /etc/issue
    chmod 644 /etc/issue.net

    echo "removing OS information from banner"
    egrep '(\\v|\\r|\\m|\\s)' /etc/motd
    egrep '(\\v|\\r|\\m|\\s)' /etc/issue
    egrep '(\\v|\\r|\\m|\\s)' /etc/issue.net
}

# Check if root
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

#####################################################
function FilesystemConfiguration 
#####################################################
{
    # Requirement 1.1.1
    if [ ! -d /filesystems ]
    then
        mkdir /filesystems
        touch /filesystems/tmp_fs
        dd if=/dev/zero of=/filesystems/tmp_fs bs=1M count=5000000
        /sbin/mkfs.ext3 -j /filesystems/tmp_fs
    fi
    # Requirement 1.1.2, 1.1.3, 1.1.4
    if ! [[ $(grep -m 1 /filesystems/tmp_fs /etc/fstab) ]];
    then
        echo "/filesystems/tmp_fs /tmp ext3 loop,rw,noexec,nosuid,nodev 0 0" >> /etc/fstab
    fi

    # Requirement 1.1.5 - Create separate partition for /var
    if [ ! -f /filesystems/var-backup ]
    then
        touch /filesystems/var_fs
        dd if=/dev/zero of=/filesystems/var_fs bs=1M count=5000000
        /sbin/mkfs.ext3 -j /filesystems/var_fs
    fi

    # Requirement 1.1.6 - Bind mount the /var/tmp directory to /tmp
    mount --bind /tmp /var/tmp none bind 0 0

    # Requirement 1.1.7 - create separate partition for /var/log
    if [ ! -f /filesystems/log_fs ]
    then
        touch /filesystems/log_fs
        dd if=/dev/zero of=/filesystems/log_fs bs=1M count=5000000
        /sbin/mkfs.ext3 -j /filesystems/log_fs
    fi

    # Requirement 1.1.8 - create separate partition for /var/log/audit
    if [ ! -f /filesystems/log_fs ]
    then
        touch /filesystems/audit_fs
        dd if=/dev/zero of=/filesystems/audit_fs bs=1M count=5000000
        /sbin/mkfs.ext3 -j /filesystems/audit_fs
    fi

    # Requirement 1.1.9 - create separate partition for /home
    if [ ! -f /filesystems/home_fs ]
    then
        touch /filesystems/home_fs
        dd if=/dev/zero of=/filesystems/home_fs bs=1M count=5000000
        /sbin/mkfs.ext3 -j /filesystems/home_fs
    fi

    # Requirement 1.1.10 - Add nodev option to /home 

    # Requirement 1.1.14 - Add nodev option to /dev/shm partition 

    # Requirement 1.1.15 - Add nosuid option to /dev/shm partition 

    # Requirement 1.1.16 - Add noexec option to /dev/shm partition 

    # Requirement 1.1.17 - Set sticky bit on all world-writeable directories 
    find / -type d -perm -0002 2>/dev/null | chmod a+t

    # Disabling Mounting of particular Filesystems
    if [ ! -f /etc/modprobe.d/CIS ]
    then
        echo "disabling the mounting of some filessystems"
        touch /etc/modprobe.d/CIS
        echo "install freevxfs /bin/true" >> /etc/modprobe.d/CIS
        echo "install jffs2 /bin/true" >> /etc/modprobe.d/CIS
        echo "install hfs /bin/true" >> /etc/modprobe.d/CIS
        echo "install hfsplus /bin/true" >> /etc/modprobe.d/CIS
        echo "install squashfs /bin/true" >> /etc/modprobe.d/CIS
        echo "install udf /bin/true" >> /etc/modprobe.d/CIS
    fi
} 

AdditionalProcessHardening
LoggingAndAuditing
NetworkConfiguration
ConfigurePAM
RemoveLegacyServices
SecureBootSettings
SElinuxConfiguration 
SoftwareUpdateConfiguration
SpecialServices
ConfiguringUserAccounts
SystemMaintenance
SetWarningBanner
SystemAccessAndAuth 
#FilesystemConfiguration 
