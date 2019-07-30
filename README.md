# CheckEvent
Perl script to check Windows event viewer or Linux error log.
To install you require Net::SSH::Perl:

$ **curl -L http://cpanmin.us | perl - --sudo App::cpanminus**

$ **sudo cpanm Net::SSH::Perl**

To send notification you need an MTA (postfix, sendmail) installed on your system.
