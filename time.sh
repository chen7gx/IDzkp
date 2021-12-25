START_TIME=`date +%s%N`
END_TIME=`date +%s%N`
#此处添加要执行的命令
for ((i=1;i<21;i++))
do 
	START_TIME=`date +%s%N`
	zokrates compute-witness -a $i 10
	zokrates generate-proof
END_TIME=`date +%s%N` 
EXECUTING_TIME[$i]=`expr $END_TIME - $START_TIME`
done

for ((i=1;i<21;i++))
do
echo ${EXECUTING_TIME[$i]}
done
