#!/bin/bash

source /home/oracle/.bash_profile      # Sets the Database Environment for oracle user e.g. ORACLE_HOME, ORACLE_SID, PATH etc.

LOG=/db02/dailybackup/logs/backup_DB_`date +%d-%b-%Y`.log  # Creates a new log for every day.
touch $LOG					           # Creates a new log for every day.

date >> $LOG

echo " " >> $LOG
echo "***************" >> $LOG
echo " " >> $LOG

echo "Putting the Database in Backup Mode." >> $LOG

cd /db02/dailybackup
sqlplus "/as sysdba" <<EOF
set time on;
spool temp1.log;
alter system archive log current;
alter database begin backup;
select count(*) from v\$backup where status='ACTIVE';
exit;
spool off;
EOF

echo " " >> $LOG
cat /db02/dailybackup/temp1.log >> $LOG
rm /db02/dailybackup/temp1.log

echo " " >> $LOG
echo "Database has been put in Backup Mode." >> $LOG
echo " " >> $LOG

echo "Backing up the Database." >> $LOG
mkdir /db02/dailybackup/`date +%d-%b-%Y`		# Creates a new backup directory for each day.
cp -RH /db01/oracle /db02/dailybackup/`date +%d-%b-%Y`

echo " " >> $LOG
echo "Database has been backed up." >> $LOG

echo " " >> $LOG
date >> $LOG
echo " " >> $LOG

echo "Bringing the Database out of Backup Mode and switching logs." >> $LOG
echo " " >> $LOG

cd /db02/dailybackup
sqlplus "/as sysdba" <<EOF
set time on;
spool temp2.log;
alter system archive log current;
alter database end backup;
select count(*) from v\$backup where status='ACTIVE';
alter system archive log current;
alter system switch logfile;
alter system switch logfile;
alter system switch logfile;
exit;
spool off;
EOF

cat /db02/dailybackup/temp2.log >> $LOG
rm /db02/dailybackup/temp2.log

echo " " >> $LOG
echo "Database is out of Backup Mode now." >> $LOG
echo " " >> $LOG

echo "Backing up the Archive Logs." >> $LOG
cp -RH /arch01/archives /db02/dailybackup/`date +%d-%b-%Y`

echo " " >> $LOG
date >> $LOG

echo " " >> $LOG
echo "Archive Logs have been backed up." >> $LOG

echo " " >> $LOG
echo "Backup Completed for `date +%d-%b-%Y`." >> $LOG
echo " " >> $LOG

echo "###############" >> $LOG

#####################################################
