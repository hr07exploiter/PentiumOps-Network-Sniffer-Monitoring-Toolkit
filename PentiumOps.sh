
#!/bin/bash


#color codes
red_color='\033[1;31;49m'
green_color='\033[1;32;49m'
yellow_color='\033[1;33;49m'
darkblue_color='\033[1;34;49m'
pink_color='\033[1;35;49m'
blue_color='\033[1;36;49m'
end_color='\033[0;37;49m\033[39;49m'

#check for root prevelages
if [[ $EUID -ne 0 ]];then
	echo -e "${red_color}You must be root user to sniff packets over Network${end_color}"
	exit 1
fi

#set the terminal size and zoom level
printf '\e[8;100;168t'
printf '\e[3;0;0t'

heading=`cat ./banners/logo.txt`

#delete the file that is passed to this function if exits
delOutFile(){
if [[ -f $1 ]];then
	rm $1
fi
}

#infinite loop
until [ 1 -eq 1];do
	clear
	echo -e "$heading"
	echo -e "${green_color}\t\t\t1.Sniff Network Packets"
	echo -e "\t\t\t2.Filter packets"
	echo -e "\t\t\t3.Open previously Captured Packets"
	echo -e "\t\t\t4.Exit\n\n"
	read -p "[*]Enter your option [NUMBER] :" option
	case $option in
	[1])     
		#Sniff Network Packets
		
		echo -e "${green_color}[*]Select packet unpacking mode\n\t\t1.)Breifly\n\t\t2.)Verbosly${end_color}"
		read -p "[*]Enter you option [NUMBER] :" unpackoption
		echo $unpackoption > sniffingdepth
		echo "0">loading
		echo -e "${green_color}[*]Started sniffing raw Network packets....!${end_color}"
		touch output.raw
		python2 PentiumOpsLoader.py
		echo -e "\n${green_color}[*]Do you want to save the file?${end_color}" 
		read -p "[y/n]:" result
		if [ "$result" == "y" ];then
			nofile=1
		
			#loops until filename to save doesn't exits

			until [ $nofile -eq 0 ];do
				echo -e "${green_color}[*]Enter the name to save the file!${end_color}" 
				read -p"File Name:" name			
					if [[ -e "./savedfiles/${name}" ]];then
						echo -e "${red_color}[*] ./savedfile/${name} already exists..!${end_color}"
						read -p"Do you want to replace it(y/n):" replace
						if [ $replace == "y" ];then
							nofile=0;
						else
							nofile=1;
						fi
					else
						nofile=0
					fi
			done
			echo "pentiumopsend">>output.raw
			cp output.raw ./savedfiles/$name
			path=`pwd`
			echo -e "${green_color}[*]File saved as ${path}/savedfiles/${name}"
		fi
		
		#deleting the temporarly used files

		delOutFile "output.raw"
		delOutFile "sniffingdepth"
		delOutFile "loading"
	;;
	[2])
		#filter packets

		echo -e "${blue_color}[*] This option works only when you are running option 1) in other terminal...!${end_color}"
		read -p"Do you want to contiue[y/n]:" result
		if [ "$result" == "y" ];then
			if [ -f "output.raw" ];then
				echo -e "${green_color}Started filter on the sniffed packets....!${end_color}"
				echo "1">loading
				echo "1">sniffingdepth
				echo "0">fromFile
				python2 PentiumOpsLoader.py
				delOutFile "loading"
				delOutFile "fromFile"
				delOutFile "sniffingdepth"	
			else
				echo -e "${red_color}You are not running option 1) in other terminal.....!${end_color}"
		
			fi
		fi
	;;
	[3])	
		#open previously saved packets file

		path=`pwd`
		echo -e "${blue_color}[*]File should be in ${path}/savedfiles/ directory....!${end_color}"
		read -p"File name:" savefile
		if [ -f ./savedfiles/$savefile ];then
			cp ./savedfiles/$savefile output.raw
			echo -e "[*]${green_color}Opening ${path}/savedfiles/${savefile} .....${end_color}"
			echo "1">loading
			echo "1">sniffingdepth
			echo "1">fromFile
			python PentiumOpsLoader.py
			delOutFile "output.raw"
			delOutFile "loading"
			delOutFile "sniffingdepth"
			delOutFile "fromFile"
		else
			echo -e "${red_color}[*]${savefile} not found !!${end_color}"
			echo -e "${blue_color}[*]File should in the ${path}/savedfiles/ directory....!!!!${end_color}"
			
		fi
		
		delOutFile "output.raw"
		delOutFile "sniffingdepth"
		;;
	[4])
		#exiting the application

		exit 0
		;;
	*)	
		
		echo -e "${red_color}[*]This option is not valid!!!${end_color}"
		;;
	esac
	echo -e "${darkblue_color}"
	read -p "Enter any key.........:)" useless
	echo -e "${end_color}"
done

