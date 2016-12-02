# init database for NS
# Execute this script using root user
# 1st: create file /etc/NSCONFIG like this
errfuc()
{
	echo "Invalide configure file /etc/NSCONFIG"
	exit 1
}
dbuser=$(cat /etc/NSCONFIG |cut -d'/' -f1)
[ "x$dbuser" = "x" ] && errfuc
dbpass=$(cat /etc/NSCONFIG |cut -d'/' -f2|cut -d'@' -f1)
[ "x$dbpass" = "x" ] && errfuc
dbhost=$(cat /etc/NSCONFIG |cut -d'@' -f2)
[ "x$dbhost" = "x" ] && errfuc
echo "1st: using the following command to create DB user"
#tmpf=$(mktemp)
echo "CREATE USER '$dbuser'@'$dbhost' IDENTIFIED BY '$dbpass'; "
echo "2nd: Grant privileges to $dbuser"
echo "create database cns_db; GRANT all ON cns_db.* TO '$dbuser'@'$dbhost' WITH GRANT OPTION; "
echo "3rd: using the following command to create DB table"
echo "mysql -u$dbuser -p$dbpass -h$dbhost < $PWD/Cns_mysql_tbl.sql"
#unlink $tmpf

