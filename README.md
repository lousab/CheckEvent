# CheckEvent
Perl script to check Windows event viewer or Linux error log.
To install you require Net::SSH::Perl:


$ **curl -L http://cpanmin.us | perl - --sudo App::cpanminus**
$ **sudo cpanm Net::SSH::Perl**


To send notification you need an MTA (postfix, sendmail) installed on your system.
You need also a parsing configuration file to retrieve data form hosts written like:

*hostname,W,put_yr_ip,useername,pwd #-----> where W or L stands for Windows or Linux s.o.*

To launch the check you could (one time) or you a cron job calling **check.sh**:
$ **sudo perl checkevent.pl -c checkevent.conf -d 1**
