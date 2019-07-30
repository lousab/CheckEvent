#!/usr/bin/perl
use strict;
use Data::Dumper;
use Getopt::Long;
use Net::SMTP;
use Net::SSH::Perl;

my ($opt_c,$opt_d);
Getopt::Long::Configure('bundling');
GetOptions(
        "c=s"   => \$opt_c, "configuration"     => \$opt_c,
        "d=s"   => \$opt_d, "days"              => \$opt_d
        );

# OPEN_FILE
# INPUT: file name
# OUTPUT: file handler
# Opens a file for reading

sub open_file(@) {
        my $filename=shift;
        open my $bin_fh, $filename or die qq{CRITICAL - Cannot open file $filename\n$!\n};
        return $bin_fh;
};

# CLOSE_FILE
# INPUT: file handler
# OUTPUT: --
# Closes a file

sub close_file(@) {
        my $bin_fh= shift;
        close $bin_fh;
};

# CONF_TO_HOH
# INPUT: file handler
# OUTPUT: hashmap with file content
# Loads configuration from a comma separated file. Expected ORDERED values are: hostname,ip,username,password
sub conf_to_hoh(@) {
        my $filehandle=shift;
        my %hashmap;
        foreach (<$filehandle>) {
                chomp $_;
                my @array = split (qq{,},$_);
                my $key = shift @array;
                foreach ( @array) {
                        $hashmap{$key}{qq{OS}} = shift @array;
                        $hashmap{$key}{qq{IP}} = shift @array;
                        $hashmap{$key}{qq{US}} = shift @array;
                        $hashmap{$key}{qq{PW}} = shift @array;
                        $hashmap{$key}{qq{ST}} = 1;
                };
        };
        return %hashmap;
};

# WMI_CMD
# INPUT: User, Pass, Host, WMIC preformatted query
# OUTPUT: WMIC query output (string)
# Runs a WMIC query and returns the result

sub wmi_cmd (@) {
        my $l_user = shift;
        my $l_pass = shift;
        my $l_host = shift;
        my $l_query = shift;
        my $cmd = qq{wmic -U $l_user\%$l_pass //$l_host "$l_query"};
        my $output = `$cmd 2>&1`;
        if ( $output =~ /NTSTATUS/) {
                        print qq{UNKNOWN - WMI Query Error (either credentials are wrong or server is unreachable)\n};
                        };
        return $output;
};

# EXEC_SSH_CMD
# INPUT: Hostname/ip, username, password, command
# OUTPUT: hashmap with command STDOUT, STDERR and EXIT CODE
# Executes a remote command and reports output locally

sub exec_ssh_cmd(@) {
        my $l_host=shift;
        my $l_user=shift;
        my $l_pass=shift;
        my $l_cmd=shift;
        my $ssh = Net::SSH::Perl->new($l_host);
        $ssh->login($l_user,$l_pass) or die qq{CRITICAL - Unable to login to $l_host (using $l_user/$l_pass)\n};
        my @retval = $ssh->cmd($l_cmd);
        my %ret_hash;
        foreach (@retval) {
                my $out=shift @retval;
                chomp $out;
                my $err=shift @retval;
                chomp $err;
                my $ext=shift @retval;
                chomp $ext;
                $ret_hash{OUT} = $out;
                $ret_hash{ERR} = $err;
                $ret_hash{EXT} = $ext;
        };
        return $ret_hash{OUT};
};

# CHECK_EVENTLOG
# INPUT: User, Pass, Host, EventLog, Days, Severity
# OUTPUT: Number of events
# Returns number of events in last N days in specified eventlog

sub check_eventlog (@) {
        my $l_user = shift;
        my $l_pass = shift;
        my $l_host = shift;
        my $l_log = shift;
        my $l_day = shift;
        my $l_severity = shift;
        my $today=`date -d -$l_day +%Y%m%d000000.000000-000`;
        chop $today;
        my $l_query=qq{SELECT EventCode,Message,TimeGenerated from Win32_NTLogEvent where LogFile='$l_log' and Type= '$l_severity' and TimeGenerated>'$today' and EventCode != '1111' and EventCode != '1107' and EventCode != '11'};
        my $output=wmi_cmd($l_user, $l_pass, $l_host, $l_query);
        if ($output eq '' ) {
                return 0;
        };
        my @output=split(q/\n/,$output);
        shift(@output);
        shift(@output);
        return @output;
};

### MAIN

my $fh=open_file($opt_c);
my %configuration=conf_to_hoh($fh);
my $mailcontent;
my $days=$opt_d.qq{days};
foreach my $key (sort keys %configuration) {
	if ( $configuration{$key}{OS} eq qq{W} ) {
	        	my $sys_title=qq{\n $key -- System Log \n};
	        	my @result=check_eventlog($configuration{$key}{US},$configuration{$key}{PW},$configuration{$key}{IP},qq{System},$days,qq{Error});
	        	my $system_log=join('',@result);
        		my $app_title=qq{\n$key -- Application Log \n};
	        	@result=check_eventlog($configuration{$key}{US},$configuration{$key}{PW},$configuration{$key}{IP},qq{Application},$days,qq{Error});
        		my $application_log=join('',@result);
	        	$mailcontent=$mailcontent.qq{#####\n\n}.$sys_title.$system_log.$app_title.$application_log.qq{\n};
        		print qq{.};
        	} else {
			my $sys_title=qq{\n $key -- System Log \n};
			my $command=qq{egrep -v "snmp|repeated|ntpd|Getting\ status|rotating|Subscription" /var/log/messages | grep "`date +\%b\\ \%d`"};
	        	my $result=exec_ssh_cmd($configuration{$key}{IP},$configuration{$key}{US},$configuration{$key}{PW},$command);
	        	my $system_log=join('',$result);
        		my $kern_title=qq{\n$key -- Kernel Log \n};
			my $command=qq{egrep -v "snmp|repeated|ntpd|Getting\ status|rotating|Subscription" /var/log/kernel | grep "`date +\%b\\ \%d`"};
	        	$result=exec_ssh_cmd($configuration{$key}{IP},$configuration{$key}{US},$configuration{$key}{PW},$command);
        		my $kernel_log=join('',$result);
	        	$mailcontent=$mailcontent.qq{#####\n\n}.$sys_title.$system_log.$kern_title.$kernel_log.qq{\n};
        		print qq{*};
		};
	};
	### mail è chi la manda 		
print qq{\n};
my $smtp =Net::SMTP->new(q{localhost});
$smtp->mail(q{mail@mail.com});
$smtp->to(q{mail@mail.it});
$smtp->cc(q{mail@mail.com});
$smtp->data();
$smtp->datasend(q{subject:[MyINFRA] Check Event output});
$smtp->datasend(qq{\n});
$smtp->datasend($mailcontent);
$smtp->datasend(qq{\n});
$smtp->dataend();
$smtp->quit;
