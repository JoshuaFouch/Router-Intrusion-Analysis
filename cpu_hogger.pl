#!/usr/bin/perl

use strict;
use warnings;

#open file
my $file = $ARGV[0];
open(FILE, "<", $file) or die "COULD NOT OPEN FILE!\n";
my @lines = <FILE>;
close(FILE);

my @Patterns;
$Patterns[0] = "GMT %SEC_LOGIN-5-LOGIN_SUCCESS: Login Success";
$Patterns[1] = "GMT %SYS-5-CONFIG_I: Configured from console by authuser1 on vty1";
$Patterns[2] = "GMT %SYS-5-PRIV_AUTH_PASS: Privilege level set";
$Patterns[3] = "GMT %OS-SYSLOG-4-LOG_WARNING : PAM detected CPU hog for cpu_hogger on 0_RP0_CPU0";
$Patterns[4] = "GMT %OS-SYSLOG-4-LOG_WARNING : PAM detected \/misc\/config is full on 0_1_CPU0";

my $matched = 0;
my $intrusion = 1;
my $startdate;
my $found = 0;

#traverse the file
foreach(@lines) {
	#if last pattern found, store the mach, and add the matched line into the hash
	if(/(^[a-z]*[0-9].[a-z]*[0-9])-(.*) ($Patterns[4])/) {
		my $mach = $1;	#store the machine
		my $Lastdate = $2;	#store the date
		foreach(@lines) {
			if(/(^$mach)-(.*) ($Patterns[0])/) {
				$startdate = $2;
				$matched = 1;
			}	
			if (/(^$mach)-(.*) ($Patterns[1])/) {
				if ($matched > 1 || $matched < 1) {
					$matched = 0;
				} else {
					$matched = 2;
				}
			}
			if (/(^$mach)-(.*) ($Patterns[2])/) {
				if ($matched > 2 || $matched < 2) {
					$matched = 0;	
				} else {
				$matched = 3;
				}
			}
			if (/(^$mach)-(.*) ($Patterns[3])/) {
				if ($matched == 3) {
					print "Intrusion:$intrusion at $mach\n\tStart: $startdate\n\tEnd: $Lastdate\n";	
				}
				$intrusion++;
				$matched = 0;
        $found = 1;
			}
		}
	} 
}
if ($found == 0){
  print "No intrusions found\n";
}
#end script
